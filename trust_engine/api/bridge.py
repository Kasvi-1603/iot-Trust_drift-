# trust_engine/api_bridge.py
from flask import Flask, request, jsonify
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Import your existing scorer
from trust_engine.scorer import score_device   # adjust import to match your actual module

app = Flask(__name__)

@app.route('/score', methods=['POST'])
def score():
    payload = request.get_json()
    result = score_device(payload)
    return jsonify(result)

if __name__ == '__main__':
    app.run(port=5001, debug=False)