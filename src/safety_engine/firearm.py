from . import safe
import librosa


def firearm_detection(burp_mcp_state, config):
    """Detect firearms via acoustic signature (preferred) or muzzle flash."""

Acoustic detection:
- Load firearm audio signatures from a database (gunshot MFCC templates by weapon class)
- Compute MFCC features from current audio buffer
- Cosine similarity against database
- Handgun: 0.85+ similarity
- Rifle: 0.90+ similarity
- Shotgun: 0.80+ similarity

Visual detection (backup):
- Detect rapid point-source brightness (muzzle flash) in video frames
- Requires high FPS camera and night vision

For MVP, acoustic-only:
"""


def firearm_detection(burp_mcp_state):
    if not hasattr(burp_mcp_state, 'audio_buffer'):
        return False

    audio = np.array(burp_mcp_state['audio_buffer'])  # shape: (num_samples, sample_rate)

    # Extract MFCCs
    mfcc = librosa.feature.mfcc(y=audio, sr=config['sample_rate'], n_mfcc=13)
    mfcc_flat = mfcc.reshape(-1, 139)  # 13 frames x 13 coefficients

    # Cosine similarity against database of known signatures
    database_signatures = load_from('firearm_signatures.db')  # pre-computed MFCC vectors
    sims = cosine_similarity(mfcc_flat, database_signatures)

    max_sim = np.max(sims)
    if max_sim > 0.85:
        weapon_class = classify_by_max_similarity(sims, database_signatures)
        safe.log_safety_event(
            event_type='firearm_detected',
            details=f'Firearm detected: {weapon_class} ({max_sim*100:.1f}% confidence)',
            severity='high'
        )
        return True

    return False
