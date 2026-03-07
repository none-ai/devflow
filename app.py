from flask import Flask, render_template, request, jsonify
import subprocess
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.json
    code = data.get('code', '')
    language = data.get('language', 'python')
    
    # 模拟代码审查
    issues = []
    
    if 'TODO' in code or 'FIXME' in code:
        issues.append({"type": "warning", "msg": "Found TODO/FIXME comments"})
    if len(code.split('\n')) > 100:
        issues.append({"type": "info", "msg": "Consider breaking down into smaller functions"})
    if 'print' in code and language == 'python':
        issues.append({"type": "style", "msg": "Remove debug print statements"})
    if 'eval(' in code:
        issues.append({"type": "error", "msg": "Security: Avoid using eval()"})
    if 'password' in code.lower() or 'secret' in code.lower():
        issues.append({"type": "security", "msg": "Potential hardcoded secret detected"})
    
    return jsonify({
        "issues": issues,
        "score": max(0, 100 - len(issues) * 10),
        "lines": len(code.split('\n'))
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
