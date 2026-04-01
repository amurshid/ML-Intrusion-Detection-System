from flask import Flask, jsonify
from scapy.all import sniff
import pickle
import numpy as np

app = Flask(__name__)

# Load model and scaler once at startup
with open('intrusion_detector_model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('min_max_scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)


def sniff_and_analyze():
    """Sniff 3 seconds of traffic, return formatted breakdown and raw counts."""
    raw = {'ARP': 0, 'ICMP': 0, 'TCP': 0, 'UDP': 0, 'Other': 0}

    packets = sniff(iface="wlan0", timeout=3, store=True)

    for packet in packets:
        if 'ARP' in packet:
            raw['ARP'] += 1
        elif 'ICMP' in packet:
            raw['ICMP'] += 1
        elif 'IP' in packet:
            if 'TCP' in packet:
                raw['TCP'] += 1
            elif 'UDP' in packet:
                raw['UDP'] += 1
            else:
                raw['Other'] += 1
        else:
            raw['Other'] += 1

    total = len(packets)
    breakdown = {}
    for proto, count in raw.items():
        pct = (count / total * 100) if total > 0 else 0
        breakdown[proto] = f"{count} packets ({pct:.1f}%)"

    return raw, breakdown


def run_ml_inference(raw_counts):
    """Build feature vector, scale, and predict. Returns label and confidence."""
    arp   = raw_counts['ARP']
    icmp  = raw_counts['ICMP']
    tcp   = raw_counts['TCP']
    udp   = raw_counts['UDP']
    other = raw_counts['Other']

    icmp_ratio = icmp / (udp + 1)
    arp_ratio  = arp  / (udp + 1)

    features = np.array([[arp, icmp, tcp, udp, other, icmp_ratio, arp_ratio]])
    features_scaled = scaler.transform(features)

    prediction = int(model.predict(features_scaled)[0])
    probabilities = model.predict_proba(features_scaled)[0]
    confidence = float(round(max(probabilities) * 100, 1))

    return prediction, confidence


@app.route('/analyze')
def analyze():
    try:
        raw_counts, breakdown = sniff_and_analyze()
        prediction, confidence = run_ml_inference(raw_counts)

        verdict = "MALICIOUS" if prediction == 1 else "Normal"

        return jsonify({
            'protocol_breakdown': breakdown,
            'ml_verdict': verdict,
            'confidence': f"{confidence}%",
            'raw_counts': raw_counts
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
