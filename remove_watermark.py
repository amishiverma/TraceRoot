import cv2
import numpy as np
import subprocess
import os
import sys

def crop_watermark(input_path, output_path, crop_pixels_bottom=45, crop_pixels_right=45):
    """
    Option 1: Clean Crop Method
    Trims off a small strip from the bottom and right edges where the watermark lives,
    preserving the aspect ratio without distorting the main composition.
    """
    if not os.path.exists(input_path):
        print(f"Warning: Input file does not exist: {input_path}")
        return

    # First, get video dimensions using ffprobe
    cmd_probe = f"ffprobe -v error -select_streams v:0 -show_entries stream=width,height -of csv=s=x:p=0 '{input_path}'"
    res = subprocess.run(cmd_probe, shell=True, capture_output=True, text=True)
    
    if not res.stdout.strip():
        print(f"Error: Unable to probe video dimensions for {input_path}. Ensure ffmpeg/ffprobe is installed.")
        return

    try:
        w, h = map(int, res.stdout.strip().split('x'))
    except Exception as e:
        print(f"Failed to parse dimensions '{res.stdout.strip()}': {e}")
        return
    
    new_w = w - crop_pixels_right
    new_h = h - crop_pixels_bottom
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # FFmpeg crop filter: crop=w:h:x:y
    cmd = f"ffmpeg -y -i '{input_path}' -vf 'crop={new_w}:{new_h}:0:0' -c:v libx264 -crf 18 -c:a copy '{output_path}'"
    print(f"Running crop command on {input_path}...")
    subprocess.run(cmd, shell=True)
    print(f"Saved cropped video to: {output_path}")

def inpaint_watermark(input_path, output_path, box_y_ratio=0.85, box_x_ratio=0.80):
    """
    Option 2: Inpainting Method (Reconstructs the background beneath the watermark)
    Use this if you cannot afford to lose any pixels from the frame boundaries.
    """
    if not os.path.exists(input_path):
        print(f"Warning: Input file does not exist: {input_path}")
        return

    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        print(f"Error: Could not open video file: {input_path}")
        return

    fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    temp_output = "temp_inpainted.mp4"
    out = cv2.VideoWriter(temp_output, fourcc, fps, (width, height))
    
    # Define watermark bounding box region (bottom-right default)
    startY = int(height * box_y_ratio)
    startX = int(width * box_x_ratio)
    
    print(f"Inpainting video frames for {input_path}... (This may take a moment)")
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
            
        # Create a mask for the watermark zone
        mask = np.zeros(frame.shape[:2], dtype=np.uint8)
        mask[startY:height, startX:width] = 255
        
        # Inpaint using Telea or Navier-Stokes algorithm
        inpainted_frame = cv2.inpaint(frame, mask, inpaintRadius=3, flags=cv2.INPAINT_TELEA)
        out.write(inpainted_frame)
        
    cap.release()
    out.release()
    
    # Merge original audio back using ffmpeg
    cmd = f"ffmpeg -y -i {temp_output} -i '{input_path}' -c:v libx264 -crf 18 -c:a aac -map 0:v:0 -map 1:a:0? -shortest '{output_path}'"
    subprocess.run(cmd, shell=True)
    if os.path.exists(temp_output):
        os.remove(temp_output)
    print(f"Saved inpainted video to: {output_path}")

if __name__ == "__main__":
    # Determine video paths (auto-detecting project assets location)
    video_targets = []

    # Check for actual repository video assets in frontend/src/assets/videos/
    repo_video_dir = os.path.join("frontend", "src", "assets", "videos")
    generic_video_dir = os.path.join("assets", "video")

    if os.path.isdir(repo_video_dir):
        cleaned_dir = os.path.join(repo_video_dir, "cleaned")
        os.makedirs(cleaned_dir, exist_ok=True)
        for fname in ["logovideo.mp4", "logo_video.mp4", "heropg.mp4"]:
            src = os.path.join(repo_video_dir, fname)
            if os.path.exists(src):
                base_name = os.path.splitext(fname)[0]
                dst = os.path.join(cleaned_dir, f"{base_name}_clean.mp4")
                video_targets.append((src, dst))

    # Also support standard assets/video/ paths if present
    if os.path.isdir(generic_video_dir) or not video_targets:
        cleaned_dir = os.path.join(generic_video_dir, "cleaned")
        os.makedirs(cleaned_dir, exist_ok=True)
        video_targets.extend([
            (os.path.join(generic_video_dir, "logo_video.mp4"), os.path.join(cleaned_dir, "logo_video_clean.mp4")),
            (os.path.join(generic_video_dir, "heropg.mp4"), os.path.join(cleaned_dir, "heropg_clean.mp4")),
        ])

    print("Target video operations queued:")
    for src, dst in video_targets:
        print(f"  • {src} -> {dst}")
        # Option 1 (Recommended for clean edges): Crop method
        if os.path.exists(src):
            crop_watermark(src, dst)
        else:
            print(f"    (Skipping: file not found at {src})")
