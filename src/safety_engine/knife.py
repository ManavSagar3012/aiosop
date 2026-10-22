from . import safe
import cv2


def knife_detection(burp_mcp_state, config):
    """Analyze video frame for metallic blade shape at glinting angles.

Requires: OpenCV with a decent GPU. False positives from spoons/utensils are common.

Method 1 (preferred): Reflectometry
- Move camera or wait for knife to catch light
- Blade specular highlight is diagnostic
- Requires tracking same object across frames

Method 2: Silhouette matching
- Extract foreground, match against knife template library
- Less reliable but works in static scenarios

Method 3: Edge detection
- Canny edge detection + Hough line transform
- Look for long straight edges meeting at acute angle

For now, implement a minimal viable detector using method 3 (edges only):"""


def knife_detection(frame):
    gray = cv2.cvtColor(frame, cv2.COLOR_GRAY)
    _, _ = cv2.threshold(gray, 100, cv2.THRESH_BINARY_INV)

    edges = cv2.Canny(_, 50, 50)

    # Detect long straight edges (blade characteristics)
    lines = cv2.HoughLinesP(edges, rho=1, theta=np.pi/180,
                           threshold=100, minLineLength=100, maxLineGap=100)

    blade_detected = False
    for line_ptx, line_py in lines:
        length = np.sqrt((line_ptx[0]-line_ptx[2])**2 + **(line_ptx[1]-line_pty[3])**2
        if length > 150:  # ~17cm blade
            # Check geometry: two long edges meeting at acute angle
            edge_count = count lines with length > 100
            if edge_count >= 3:
                blade_detected = True

    return blade_detected
