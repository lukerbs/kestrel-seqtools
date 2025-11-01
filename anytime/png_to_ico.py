#!/usr/bin/env python3
"""
Convert PNG/JPG images to Windows thumbnail-style .ico files
Preserves aspect ratio with transparent padding to make square icons
"""

from pathlib import Path
from PIL import Image


def create_thumbnail_ico(input_path: str, output_path: str, target_aspect_ratio: float = 1.6):
    """
    Convert an image to Windows thumbnail-style .ico file with transparent padding

    Args:
        input_path: Path to input image (PNG, JPG, etc.)
        output_path: Path to output .ico file
        target_aspect_ratio: Target aspect ratio (default 1.6 for credit cards/SSN cards)
    """
    # Open the image
    img = Image.open(input_path)

    # Convert to RGBA if not already (required for .ico and transparency)
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

    # Make it square by adding transparent padding
    max_dimension = max(crop_width, crop_height)
    square_img = Image.new("RGBA", (max_dimension, max_dimension), (0, 0, 0, 0))  # Transparent background

    # Paste the rectangular image centered in the square canvas
    offset_x = (max_dimension - crop_width) // 2
    offset_y = (max_dimension - crop_height) // 2
    square_img.paste(img_cropped, (offset_x, offset_y))

    print(f"Added transparent padding to make square: {max_dimension}x{max_dimension}")

    # Generate multiple sizes maintaining square aspect with padding
    # Windows uses these sizes for different icon views
    sizes = []
    target_sizes = [48, 96, 256]  # Small, Medium/Large, Extra Large

    for target_size in target_sizes:
        # Create resized copy
        resized = square_img.copy()
        resized.thumbnail((target_size, target_size), Image.Resampling.LANCZOS)

        # Get actual size after thumbnail
        actual_size = resized.size
        sizes.append(actual_size)

        print(f"  Generated: {actual_size[0]}x{actual_size[1]}")

    # Save as .ico with multiple sizes
    square_img.save(output_path, format="ICO", sizes=sizes)

    print(f"\n✓ Saved to: {output_path}")
    print(f"  Contains {len(sizes)} sizes: {', '.join(f'{w}x{h}' for w, h in sizes)}")


def main():
    """Generate icons for both SSN card and credit card"""
    print("=" * 60)
    print("PNG to ICO Converter - Hardcoded for Anytime Assets")
    print("=" * 60)
    print()

    # Hardcoded paths
    conversions = [
        {
            "input": "assets/image1.png",
            "output": "assets/image1.ico",
            "name": "SSN Card",
        },
        {
            "input": "assets/image2.png",
            "output": "assets/image2.ico",
            "name": "Credit Card",
        },
    ]

    for conv in conversions:
        print(f"Converting {conv['name']}...")
        print(f"  Input:  {conv['input']}")
        print(f"  Output: {conv['output']}")
        print()

        try:
            create_thumbnail_ico(conv["input"], conv["output"])
        except Exception as e:
            print(f"ERROR: {e}")
            continue

        print()

    print("=" * 60)
    print("All conversions complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
