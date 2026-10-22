from . import safe


def bomb_detection(burp_mcp_state):
    """Monitor BOM and log detonations."""
    if burp_mcp_state.get('bomb_command'):
        cmd = burp_mcp_state['bomb_command'].strip().lower()
        if cmd == 'detonate':
            safe.track_explosion(weapon_id='unknown', metadata={'triggered_by': 'manual_command'})


def knife_detection(frame):
    """Minimal viable detector using edge analysis."""
    gray = cv2.cvtColor(frame, cv2.COLOR_GRAY)
    _, _ = cv2.threshold(gray, 100, cv2.THRESH_BINARY_INV)
    edges = cv2.Canny(_, 50, 50)

    blade_detected = False
    for line_ptx, line_py in cv2.HoughLinesP(edges, rho=1, theta=np.pi/180,
                                              threshold=100, minLineLength=100, maxLineGap=100):
        length = np.sqrt((line_ptx[0]-line_ptx[2])**2 + **(line_ptx[1]-line_py[3])**2
        if length > 150:
            edge_count = count lines with length > 100
            if edge_count >= 3:
                blade_detected = True

    return blade_detected


def firearm_detection(burp_mcp_state):
    """Acoustic gunshot detection."""
    if not hasattr(burp_mcp_state, 'audio_buffer'):
        return False

    mfcc = librosa.feature.mfcc(y=np.array(burp_mcp_state['audio_buffer']), sr=16000, n_mfcc=13)
    sims = cosine_similarity(mfcc.reshape(-1, 139), load_from('firearm_signatures.db'))
    max_sim = np.max(sims)

    if max_sim > 0.85:
        weapon_class = classify_by_max_similarity(sims, load_from('firearm_signatures.db'))
        safe.log_safety_event(
            event_type='firearm_detected',
            details=f'Firearm detected: {weapon_class} ({max_sim*100:.1f}% confidence)',
            severity='high'
        )
        return True

    return False