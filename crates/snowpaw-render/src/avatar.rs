//! Profile pictures. Image decoders are a classic source of memory-safety bugs and
//! decompression bombs, so the client never decodes a picture itself: the file the
//! user picked, and every picture fetched from the server, is decoded here, in the
//! sandbox, with hard limits on dimensions and memory.

use std::io::Cursor;

use image::imageops::FilterType;
use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};
use snowpaw_proto::profile::{AVATAR_SIDE, MAX_AVATAR_BYTES, png_dimensions};
use snowpaw_proto::render::RenderFailure;

use crate::math::Image;

/// Largest picture side we'll decode. Phone photos are ~4000-6000 px.
const MAX_SOURCE_SIDE: u32 = 8192;
/// Most memory a decoder may hold at once (a 12-megapixel photo needs ~48 MiB).
const MAX_DECODE_ALLOC: u64 = 192 * 1024 * 1024;

fn limits(side: u32, alloc: u64) -> Limits {
    let mut l = Limits::default();
    l.max_image_width = Some(side);
    l.max_image_height = Some(side);
    l.max_alloc = Some(alloc);
    l
}

/// Picked file -> upright, center-cropped, 256x256 PNG with no metadata (EXIF,
/// location, comments and color profiles are all dropped by re-encoding).
pub fn normalize(data: &[u8]) -> Result<Vec<u8>, RenderFailure> {
    let reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|_| RenderFailure::InvalidImage)?;
    // Only the formats we compiled in, identified by content (never by file name).
    if !matches!(
        reader.format(),
        Some(ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::Gif | ImageFormat::WebP)
    ) {
        return Err(RenderFailure::InvalidImage);
    }
    let mut reader = reader;
    reader.limits(limits(MAX_SOURCE_SIDE, MAX_DECODE_ALLOC));
    let mut decoder = reader.into_decoder().map_err(|_| RenderFailure::InvalidImage)?;
    let orientation = decoder.orientation().ok();
    let mut img = DynamicImage::from_decoder(decoder).map_err(|_| RenderFailure::InvalidImage)?;
    if let Some(o) = orientation {
        img.apply_orientation(o);
    }
    let (w, h) = (img.width(), img.height());
    let side = w.min(h);
    if side == 0 {
        return Err(RenderFailure::InvalidImage);
    }
    let square = img.crop_imm((w - side) / 2, (h - side) / 2, side, side);
    let out = square.resize_exact(AVATAR_SIDE, AVATAR_SIDE, FilterType::Lanczos3).into_rgba8();
    let mut png = Vec::new();
    DynamicImage::ImageRgba8(out)
        .write_to(Cursor::new(&mut png), ImageFormat::Png)
        .map_err(|_| RenderFailure::Internal)?;
    if png.len() > MAX_AVATAR_BYTES {
        return Err(RenderFailure::TooLarge);
    }
    Ok(png)
}

/// A stored profile picture -> premultiplied RGBA for display. Only 256x256 PNGs.
pub fn decode(data: &[u8]) -> Result<Image, RenderFailure> {
    if png_dimensions(data) != Some((AVATAR_SIDE, AVATAR_SIDE)) {
        return Err(RenderFailure::InvalidImage);
    }
    let side = u64::from(AVATAR_SIDE);
    let mut reader = ImageReader::with_format(Cursor::new(data), ImageFormat::Png);
    // Room for a 16-bit RGBA decode plus the 8-bit copy.
    reader.limits(limits(AVATAR_SIDE, side * side * 16));
    let img = reader.decode().map_err(|_| RenderFailure::InvalidImage)?.into_rgba8();
    if (img.width(), img.height()) != (AVATAR_SIDE, AVATAR_SIDE) {
        return Err(RenderFailure::InvalidImage);
    }
    let mut rgba = img.into_raw();
    for px in rgba.as_chunks_mut::<4>().0 {
        let a = u16::from(px[3]);
        for c in &mut px[..3] {
            // Round-to-nearest c * a / 255; the result is at most 255.
            *c = u8::try_from((u16::from(*c) * a + 127) / 255).unwrap_or(u8::MAX);
        }
    }
    Ok(Image { width: AVATAR_SIDE, height: AVATAR_SIDE, rgba })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};

    fn encode(img: DynamicImage, format: ImageFormat) -> Vec<u8> {
        let mut out = Vec::new();
        img.write_to(Cursor::new(&mut out), format).expect("encode");
        out
    }

    fn photo(w: u32, h: u32) -> DynamicImage {
        DynamicImage::ImageRgba8(ImageBuffer::from_fn(w, h, |x, y| {
            Rgba([(x % 256) as u8, (y % 256) as u8, 128, 255])
        }))
    }

    #[test]
    fn normalizes_any_supported_format_to_a_256_png() {
        for format in [ImageFormat::Png, ImageFormat::Jpeg, ImageFormat::Gif, ImageFormat::WebP] {
            let src = match format {
                ImageFormat::Jpeg => DynamicImage::ImageRgb8(photo(640, 480).into_rgb8()),
                _ => photo(640, 480),
            };
            let png = normalize(&encode(src, format)).expect("normalized");
            assert_eq!(png_dimensions(&png), Some((256, 256)), "{format:?}");
            let shown = decode(&png).expect("decodes");
            assert_eq!(shown.rgba.len(), 256 * 256 * 4);
        }
    }

    #[test]
    fn output_carries_no_metadata() {
        let png = normalize(&encode(photo(300, 300), ImageFormat::Png)).expect("normalized");
        // Walk the chunks: only the ones needed to draw pixels.
        let mut i = 8;
        while i + 8 <= png.len() {
            let len = u32::from_be_bytes([png[i], png[i + 1], png[i + 2], png[i + 3]]) as usize;
            let kind = &png[i + 4..i + 8];
            assert!(
                matches!(kind, b"IHDR" | b"IDAT" | b"IEND"),
                "{:?}",
                String::from_utf8_lossy(kind)
            );
            i += 12 + len;
        }
    }

    #[test]
    fn refuses_other_formats_and_garbage() {
        assert_eq!(normalize(b"<svg onload=alert(1)/>"), Err(RenderFailure::InvalidImage));
        assert_eq!(normalize(b"BM garbage"), Err(RenderFailure::InvalidImage));
        assert_eq!(normalize(&[0u8; 64]), Err(RenderFailure::InvalidImage));
        // Formats that aren't compiled in, by their magic bytes: TIFF, ICO, AVIF.
        for magic in [&b"II*\0........"[..], b"\0\0\x01\0\x01\0", b"\0\0\0\x1cftypavif"] {
            assert_eq!(normalize(magic), Err(RenderFailure::InvalidImage));
        }
        let mut truncated = encode(photo(64, 64), ImageFormat::Png);
        truncated.truncate(truncated.len() / 2);
        assert_eq!(normalize(&truncated), Err(RenderFailure::InvalidImage));
    }

    #[test]
    fn decompression_bombs_are_refused_before_allocating() {
        // A tiny file that claims to be 60000 x 60000: the header alone is checked
        // against the limits, so nothing near 14 GB is ever allocated.
        let png = encode(photo(1, 1), ImageFormat::Png);
        let mut bomb = png.clone();
        bomb[16..20].copy_from_slice(&60_000u32.to_be_bytes());
        bomb[20..24].copy_from_slice(&60_000u32.to_be_bytes());
        assert_eq!(normalize(&bomb), Err(RenderFailure::InvalidImage));
        // Display only takes exactly 256x256.
        assert_eq!(
            decode(&encode(photo(512, 512), ImageFormat::Png)).err(),
            Some(RenderFailure::InvalidImage)
        );
        assert_eq!(decode(&bomb).err(), Some(RenderFailure::InvalidImage));
    }

    #[test]
    fn crops_to_the_center() {
        // Left third red, middle green, right third blue: a center crop is all green.
        let src = DynamicImage::ImageRgba8(ImageBuffer::from_fn(900, 300, |x, _| match x / 300 {
            0 => Rgba([255, 0, 0, 255]),
            1 => Rgba([0, 255, 0, 255]),
            _ => Rgba([0, 0, 255, 255]),
        }));
        let png = normalize(&encode(src, ImageFormat::Png)).expect("normalized");
        let img = decode(&png).expect("decodes");
        let mid = (128 * 256 + 128) * 4;
        assert_eq!(&img.rgba[mid..mid + 4], &[0, 255, 0, 255]);
    }

    #[test]
    fn premultiplies_alpha() {
        let src =
            DynamicImage::ImageRgba8(ImageBuffer::from_pixel(256, 256, Rgba([200, 100, 0, 128])));
        let img = decode(&encode(src, ImageFormat::Png)).expect("decodes");
        assert_eq!(&img.rgba[..4], &[100, 50, 0, 128]);
    }
}
