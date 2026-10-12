//! Quizzes: a message kind agents send, and the answers the user sends back.
//!
//! The quiz (with its answer key) is stored on the server. When the user answers,
//! the client sends only their choices; the server works out which were right from
//! the stored quiz and attaches that to the stored answers. So what the agent's model
//! is told ("question 2 was wrong") never depends on what a client claims.

use serde::{Deserialize, Serialize};

use crate::Id;

pub const MAX_QUESTIONS: usize = 20;
pub const MIN_CHOICES: usize = 2;
pub const MAX_CHOICES: usize = 6;
pub const MAX_QUIZ_TITLE_CHARS: usize = 120;
pub const MAX_PROMPT_CHARS: usize = 500;
pub const MAX_CHOICE_CHARS: usize = 200;
pub const MAX_HINT_CHARS: usize = 300;
pub const MAX_EXPLANATION_CHARS: usize = 600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quiz {
    pub title: String,
    pub questions: Vec<Question>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Question {
    pub prompt: String,
    pub choices: Vec<String>,
    /// Index into `choices` of the correct answer.
    pub answer: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hint: String,
    /// Shown after answering, and on the back of the flashcard.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub explanation: String,
}

/// Why a quiz or a set of answers was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuizError {
    NoQuestions,
    TooManyQuestions,
    BadChoices,
    AnswerOutOfRange,
    /// Empty where required, too long, or a forbidden character.
    BadText,
}

impl std::fmt::Display for QuizError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NoQuestions => "a quiz needs at least one question",
            Self::TooManyQuestions => "too many questions",
            Self::BadChoices => "each question needs 2 to 6 distinct choices",
            Self::AnswerOutOfRange => "an answer points at a choice that doesn't exist",
            Self::BadText => "quiz text is empty, too long, or contains a forbidden character",
        })
    }
}

impl std::error::Error for QuizError {}

/// Plain one-paragraph-ish text: no control characters except newlines (if allowed),
/// no bidi overrides, within `max` characters, and non-empty if `required`.
fn text_ok(s: &str, max: usize, required: bool, newlines: bool) -> bool {
    if required && s.trim().is_empty() {
        return false;
    }
    s.chars().count() <= max
        && s.chars().all(|c| {
            !(c.is_control() && !(newlines && c == '\n'))
                && !('\u{202A}'..='\u{202E}').contains(&c)
                && !('\u{2066}'..='\u{2069}').contains(&c)
        })
}

impl Quiz {
    pub fn validate(&self) -> Result<(), QuizError> {
        if !text_ok(&self.title, MAX_QUIZ_TITLE_CHARS, true, false) {
            return Err(QuizError::BadText);
        }
        if self.questions.is_empty() {
            return Err(QuizError::NoQuestions);
        }
        if self.questions.len() > MAX_QUESTIONS {
            return Err(QuizError::TooManyQuestions);
        }
        for q in &self.questions {
            if !(MIN_CHOICES..=MAX_CHOICES).contains(&q.choices.len()) {
                return Err(QuizError::BadChoices);
            }
            let mut seen: Vec<&str> = q.choices.iter().map(|c| c.trim()).collect();
            seen.sort_unstable();
            seen.dedup();
            if seen.len() != q.choices.len() {
                return Err(QuizError::BadChoices);
            }
            if usize::from(q.answer) >= q.choices.len() {
                return Err(QuizError::AnswerOutOfRange);
            }
            let texts_ok = text_ok(&q.prompt, MAX_PROMPT_CHARS, true, true)
                && q.choices.iter().all(|c| text_ok(c, MAX_CHOICE_CHARS, true, false))
                && text_ok(&q.hint, MAX_HINT_CHARS, false, true)
                && text_ok(&q.explanation, MAX_EXPLANATION_CHARS, false, true);
            if !texts_ok {
                return Err(QuizError::BadText);
            }
        }
        Ok(())
    }

    /// Which answers are right, from this (stored) quiz. `answers` must already have
    /// passed `check_answers`.
    pub fn grade(&self, answers: &[Option<u8>]) -> Vec<bool> {
        self.questions.iter().zip(answers).map(|(q, a)| *a == Some(q.answer)).collect()
    }

    /// Answers fit this quiz: one per question, each a valid choice or skipped.
    pub fn check_answers(&self, answers: &[Option<u8>]) -> Result<(), QuizError> {
        if answers.len() != self.questions.len() {
            return Err(QuizError::AnswerOutOfRange);
        }
        let fits = self
            .questions
            .iter()
            .zip(answers)
            .all(|(q, a)| a.is_none_or(|a| usize::from(a) < q.choices.len()));
        if fits { Ok(()) } else { Err(QuizError::AnswerOutOfRange) }
    }
}

/// A quiz's answers as stored and shown: the choices, plus the server's grading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuizAnswers {
    /// The quiz message (its id) these answer.
    pub quiz_id: Id,
    /// One per question; `None` = skipped.
    pub answers: Vec<Option<u8>>,
    /// Filled in by the server from the stored quiz. Clients must send it empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<bool>,
}

impl QuizAnswers {
    pub fn score(&self) -> (usize, usize) {
        (self.results.iter().filter(|r| **r).count(), self.answers.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> Quiz {
        Quiz {
            title: "Capitals".into(),
            questions: vec![
                Question {
                    prompt: "Capital of Iceland?".into(),
                    choices: vec!["Reykjavík".into(), "Oslo".into(), "Akureyri".into()],
                    answer: 0,
                    hint: "Starts with R".into(),
                    explanation: String::new(),
                },
                Question {
                    prompt: "Capital of Norway?".into(),
                    choices: vec!["Bergen".into(), "Oslo".into()],
                    answer: 1,
                    hint: String::new(),
                    explanation: "Oslo since 1814.".into(),
                },
            ],
        }
    }

    #[test]
    fn valid_quiz_and_grading() {
        let q = sample();
        assert_eq!(q.validate(), Ok(()));
        assert_eq!(q.check_answers(&[Some(0), Some(0)]), Ok(()));
        assert_eq!(q.grade(&[Some(0), Some(0)]), vec![true, false]);
        assert_eq!(q.grade(&[None, Some(1)]), vec![false, true]);
    }

    #[test]
    fn broken_quizzes_are_rejected() {
        let mut q = sample();
        q.questions[0].answer = 3;
        assert_eq!(q.validate(), Err(QuizError::AnswerOutOfRange));
        let mut q = sample();
        q.questions[1].choices = vec!["Oslo".into()];
        assert_eq!(q.validate(), Err(QuizError::BadChoices));
        let mut q = sample();
        q.questions[1].choices = vec!["Oslo".into(), " Oslo".into()];
        assert_eq!(q.validate(), Err(QuizError::BadChoices), "duplicate choices");
        let mut q = sample();
        q.questions.clear();
        assert_eq!(q.validate(), Err(QuizError::NoQuestions));
        let mut q = sample();
        q.questions = vec![sample().questions[0].clone(); MAX_QUESTIONS + 1];
        assert_eq!(q.validate(), Err(QuizError::TooManyQuestions));
        for bad in ["", "a\u{202E}b", "bell\u{7}", &"x".repeat(MAX_QUIZ_TITLE_CHARS + 1)] {
            let mut q = sample();
            q.title = bad.into();
            assert_eq!(q.validate(), Err(QuizError::BadText), "{bad:?}");
        }
        let mut q = sample();
        q.questions[0].choices[1] = "two\nlines".into();
        assert_eq!(q.validate(), Err(QuizError::BadText));
    }

    #[test]
    fn answers_must_fit_the_quiz() {
        let q = sample();
        assert!(q.check_answers(&[Some(0)]).is_err(), "too few");
        assert!(q.check_answers(&[Some(0), Some(1), Some(0)]).is_err(), "too many");
        assert!(q.check_answers(&[Some(0), Some(2)]).is_err(), "no third choice in question 2");
        assert!(q.check_answers(&[None, None]).is_ok());
    }
}
