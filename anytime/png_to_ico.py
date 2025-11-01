#!/usr/bin/env python3
"""
Convert PNG/JPG images to Windows thumbnail-style .ico files
Preserves aspect ratio like real Windows image previews
"""

import sys
from pathlib import Path
from PIL import Image


def create_thumbnail_ico(input_path: str, output_path: str = None, target_aspect_ratio: float = 1.6):
    """
    Convert an image to Windows thumbnail-style .ico file

    Args:
        input_path: Path to input image (PNG, JPG, etc.)
        output_path: Path to output .ico file (optional, defaults to same name)
        target_aspect_ratio: Target aspect ratio (default 1.6 for credit cards/SSN cards)
    """
    # Open the image
    img = Image.open(input_path)

    # Convert to RGBA if not already (required for .ico)
    if img.mode != "RGBA":
        img = img.convert("RGBA")

    # Get original dimensions
    orig_width, orig_height = img.size
    orig_aspect_ratio = orig_width / orig_height

    print(f"Original image: {orig_width}x{orig_height} (aspect ratio: {orig_aspect_ratio:.2f}:1)")

    # Crop to target aspect ratio (keeping full width, cropping top/bottom centered)
    crop_width = orig_width
    crop_height = int(crop_width / target_aspect_ratio)

    if crop_height > orig_height:
        # Image is too tall even at full width, need to keep full height and crop sides instead
        crop_height = orig_height
        crop_width = int(crop_height * target_aspect_ratio)
        # Center horizontally
        left = (orig_width - crop_width) // 2
        top = 0
    else:
        # Keep full width, crop top/bottom centered
        left = 0
        top = (orig_height - crop_height) // 2

    right = left + crop_width
    bottom = top + crop_height

    # Perform the crop
    img_cropped = img.crop((left, top, right, bottom))

    print(f"Cropped to: {crop_width}x{crop_height} (aspect ratio: {target_aspect_ratio:.2f}:1)")

    # Generate multiple sizes maintaining aspect ratio
    # Windows uses these widths for different icon views
    sizes = []
    target_widths = [48, 96, 256]  # Small, Medium/Large, Extra Large

    for target_width in target_widths:
        # Calculate height to maintain aspect ratio
        target_height = int(target_width / target_aspect_ratio)

        # Create resized copy
        resized = img_cropped.copy()
        resized.thumbnail((target_width, target_height), Image.Resampling.LANCZOS)

        # Get actual size after thumbnail (might be slightly different)
        actual_size = resized.size
        sizes.append(actual_size)

        print(f"  Generated: {actual_size[0]}x{actual_size[1]}")

    # Determine output path
    if output_path is None:
        input_file = Path(input_path)
        output_path = input_file.with_suffix(".ico")

    # Save as .ico with multiple sizes
    img_cropped.save(output_path, format="ICO", sizes=sizes)

    print(f"\n✓ Saved to: {output_path}")
    print(f"  Contains {len(sizes)} sizes: {', '.join(f'{w}x{h}' for w, h in sizes)}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python png_to_ico.py <input_image> [output.ico]")
        print("\nExample:")
        print("  python png_to_ico.py ssn_card.png")
        print("  python png_to_ico.py credit_card.jpg assets/creditcard.ico")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    # Check if input file exists
    if not Path(input_path).exists():
        print(f"Error: File not found: {input_path}")
        sys.exit(1)

    try:
        create_thumbnail_ico(input_path, output_path)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
