from flask import Flask, render_template, request, jsonify, send_file
import subprocess
import os
import json
from datetime import datetime

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Language configurations
LANGUAGES = {
    'python': {
        'name': 'Python',
        'extensions': ['.py'],
        'keywords': ['def ', 'class ', 'import ', 'from ', 'if ', 'for ', 'while ']
    },
    'javascript': {
        'name': 'JavaScript',
        'extensions': ['.js', '.jsx'],
        'keywords': ['function ', 'const ', 'let ', 'var ', 'class ', 'import ', 'export ']
    },
    'java': {
        'name': 'Java',
        'extensions': ['.java'],
        'keywords': ['public ', 'private ', 'class ', 'import ', 'void ', 'static ']
    },
    'go': {
        'name': 'Go',
        'extensions': ['.go'],
        'keywords': ['func ', 'package ', 'import ', 'type ', 'struct ', 'interface ']
    },
    'rust': {
        'name': 'Rust',
        'extensions': ['.rs'],
        'keywords': ['fn ', 'let ', 'mut ', 'pub ', 'struct ', 'impl ', 'use ']
    },
    'cpp': {
        'name': 'C++',
        'extensions': ['.cpp', '.cc', '.h', '.hpp'],
        'keywords': ['#include', 'int main', 'class ', 'void ', 'std::']
    },
    'typescript': {
        'name': 'TypeScript',
        'extensions': ['.ts', '.tsx'],
        'keywords': ['interface ', 'type ', 'export ', 'const ', 'let ']
    }
}

# Analysis rules per language
ANALYSIS_RULES = {
    'python': [
        {'pattern': r'TODO|FIXME|XXX|HACK', 'type': 'warning', 'msg': 'Found TODO/FIXME comments'},
        {'pattern': r'eval\s*\(', 'type': 'error', 'msg': 'Security: Avoid using eval()'},
        {'pattern': r'exec\s*\(', 'type': 'error', 'msg': 'Security: Avoid using exec()'},
        {'pattern': r'print\s*\(', 'type': 'style', 'msg': 'Remove debug print statements'},
        {'pattern': r'password|secret|api_key|apikey|token', 'type': 'security', 'msg': 'Potential hardcoded secret detected', 'case_insensitive': True},
        {'pattern': r'os\.system\s*\(', 'type': 'error', 'msg': 'Security: Avoid os.system() - use subprocess'},
        {'pattern': r'subprocess\.call\s*\(\s*\[', 'type': 'warning', 'msg': 'Consider shell=True security implications'},
        {'pattern': r'open\s*\([^)]*\br\b', 'type': 'warning', 'msg': 'Ensure file handles are properly closed (use context manager)'},
        {'pattern': r'catch\s*Exception', 'type': 'warning', 'msg': 'Avoid catching bare Exception - be specific'},
        {'pattern': r'pass\s*$', 'type': 'info', 'msg': 'Empty code block - consider adding TODO or removing'},
    ],
    'javascript': [
        {'pattern': r'TODO|FIXME|XXX|HACK', 'type': 'warning', 'msg': 'Found TODO/FIXME comments'},
        {'pattern': r'eval\s*\(', 'type': 'error', 'msg': 'Security: Avoid using eval()'},
        {'pattern': r'console\.log\s*\(', 'type': 'style', 'msg': 'Remove console.log statements'},
        {'pattern': r'password|secret|api_key|apikey|token', 'type': 'security', 'msg': 'Potential hardcoded secret detected', 'case_insensitive': True},
        {'pattern': r'innerHTML\s*=', 'type': 'security', 'msg': 'Security: Use textContent instead of innerHTML to prevent XSS'},
        {'pattern': r'document\.write\s*\(', 'type': 'warning', 'msg': 'Avoid document.write() - use DOM methods'},
        {'pattern': r'var\s+\w+\s*=', 'type': 'info', 'msg': 'Consider using const/let instead of var'},
        {'pattern': r'==\s*[^=]', 'type': 'style', 'msg': 'Use === for strict equality'},
        {'pattern': r'catch\s*\(\s*\w*\s*\)', 'type': 'info', 'msg': 'Empty catch block - handle errors properly'},
    ],
    'java': [
        {'pattern': r'TODO|FIXME|XXX|HACK', 'type': 'warning', 'msg': 'Found TODO/FIXME comments'},
        {'pattern': r'System\.out\.print', 'type': 'style', 'msg': 'Use a logging framework instead of System.out'},
        {'pattern': r'password|secret|api_key|apikey|token', 'type': 'security', 'msg': 'Potential hardcoded secret detected', 'case_insensitive': True},
        {'pattern': r'catch\s*\(\s*Exception\s+\w+\s*\)', 'type': 'warning', 'msg': 'Avoid catching generic Exception'},
        {'pattern': r'synchronized\s*\(', 'type': 'info', 'msg': 'Consider using java.util.concurrent instead of synchronized'},
        {'pattern': r'throws\s+Exception', 'type': 'warning', 'msg': 'Avoid declaring broad exceptions'},
    ],
    'go': [
        {'pattern': r'TODO|FIXME|XXX|HACK', 'type': 'warning', 'msg': 'Found TODO/FIXME comments'},
        {'pattern': r'password|secret|api_key|apikey|token', 'type': 'security', 'msg': 'Potential hardcoded secret detected', 'case_insensitive': True},
        {'pattern': r'fmt\.Print', 'type': 'style', 'msg': 'Use structured logging'},
        {'pattern': r'panic\s*\(', 'type': 'warning', 'msg': 'Avoid using panic() for error handling'},
        {'pattern': r'func\s+\w+\s*\(\s*\w+\s+\*?(\w+)\s*\)', 'type': 'info', 'msg': 'Consider returning error instead of panicking'},
        {'pattern': r'go\s+func\s*\(', 'type': 'info', 'msg': 'Ensure goroutine is properly managed'},
    ],
    'rust': [
        {'pattern': r'TODO|FIXME|XXX|HACK', 'type': 'warning', 'msg': 'Found TODO/FIXME comments'},
        {'pattern': r'password|secret|api_key|apikey|token', 'type': 'security', 'msg': 'Potential hardcoded secret detected', 'case_insensitive': True},
        {'pattern': r'println!\s*\(', 'type': 'style', 'msg': 'Use log crate for logging'},
        {'pattern': r'unwrap\(\)', 'type': 'warning', 'msg': 'Avoid unwrap() - handle errors properly'},
        {'pattern': r'expect\(', 'type': 'warning', 'msg': 'Consider proper error handling over expect()'},
        {'pattern': r'unsafe\s*\{', 'type': 'security', 'msg': 'Review unsafe block for security implications'},
    ],
    'cpp': [
        {'pattern': r'TODO|FIXME|XXX|HACK', 'type': 'warning', 'msg': 'Found TODO/FIXME comments'},
        {'pattern': r'password|secret|api_key|apikey|token', 'type': 'security', 'msg': 'Potential hardcoded secret detected', 'case_insensitive': True},
        {'pattern': r'printf\s*\(', 'type': 'style', 'msg': 'Consider using iostreams or logging library'},
        {'pattern': r'goto\s+\w+', 'type': 'warning', 'msg': 'Avoid using goto statement'},
        {'pattern': r'std::endl', 'type': 'style', 'msg': "Use '\\n' instead of std::endl"},
        {'pattern': r'malloc\s*\(', 'type': 'warning', 'msg': 'Use new/delete or smart pointers in modern C++'},
    ],
    'typescript': [
        {'pattern': r'TODO|FIXME|XXX|HACK', 'type': 'warning', 'msg': 'Found TODO/FIXME comments'},
        {'pattern': r'password|secret|api_key|apikey|token', 'type': 'security', 'msg': 'Potential hardcoded secret detected', 'case_insensitive': True},
        {'pattern': r'console\.log\s*\(', 'type': 'style', 'msg': 'Remove console.log statements'},
        {'pattern': r'any\s*\)', 'type': 'warning', 'msg': 'Avoid using "any" type - be specific'},
        {'pattern': r'@ts-ignore', 'type': 'warning', 'msg': 'Avoid @ts-ignore - fix the type error instead'},
        {'pattern': r'innerHTML\s*=', 'type': 'security', 'msg': 'Security: Use textContent instead of innerHTML to prevent XSS'},
    ],
}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/languages', methods=['GET'])
def get_languages():
    """Get list of supported languages"""
    return jsonify({
        'languages': {k: v['name'] for k, v in LANGUAGES.items()}
    })


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyze code for issues"""
    data = request.json
    code = data.get('code', '')
    language = data.get('language', 'python')

    if not code:
        return jsonify({'error': 'No code provided'}), 400

    issues = []

    # Get language-specific rules or use Python as default
    rules = ANALYSIS_RULES.get(language, ANALYSIS_RULES.get('python', []))

    # Apply all rules
    for rule in rules:
        import re
        flags = re.IGNORECASE if rule.get('case_insensitive', False) else 0
        pattern = rule['pattern']

        matches = re.finditer(pattern, code, flags)
        for match in matches:
            # Get line number
            line_num = code[:match.start()].count('\n') + 1

            # Avoid duplicate issues on same line for same rule
            issue_key = (line_num, rule['msg'])
            if not any(i.get('line') == line_num and i['msg'] == rule['msg'] for i in issues):
                issues.append({
                    'type': rule['type'],
                    'msg': rule['msg'],
                    'line': line_num,
                    'match': match.group()[:50]  # Show first 50 chars of match
                })

    # General rules
    lines = code.split('\n')

    # Check for very long lines
    for i, line in enumerate(lines, 1):
        if len(line) > 120:
            issues.append({
                'type': 'style',
                'msg': f'Line too long ({len(line)} chars)',
                'line': i
            })

    # Check for function size (Python)
    if language == 'python':
        in_function = False
        func_start = 0
        func_lines = 0
        for i, line in enumerate(lines):
            if 'def ' in line and '(' in line:
                in_function = True
                func_start = i
                func_lines = 1
            elif in_function:
                if line and not line[0].isspace():
                    in_function = False
                    if func_lines > 50:
                        issues.append({
                            'type': 'info',
                            'msg': f'Function too long ({func_lines} lines) - consider splitting',
                            'line': func_start + 1
                        })
                elif line.strip():
                    func_lines += 1

    # Calculate score
    type_weights = {
        'error': 15,
        'security': 15,
        'warning': 8,
        'style': 3,
        'info': 1
    }

    score = 100
    for issue in issues:
        score -= type_weights.get(issue['type'], 5)

    score = max(0, score)

    # Save to history
    history_entry = {
        'timestamp': datetime.now().isoformat(),
        'language': language,
        'lines': len(lines),
        'issues_count': len(issues),
        'score': score
    }

    # Store in memory (in production, use a database)
    if not hasattr(app, 'history'):
        app.history = []
    app.history.insert(0, history_entry)
    app.history = app.history[:50]  # Keep last 50

    return jsonify({
        'issues': issues,
        'score': score,
        'lines': len(lines),
        'language': language,
        'language_name': LANGUAGES.get(language, {}).get('name', language.capitalize())
    })


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload and analyze a file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Detect language from extension
    ext = os.path.splitext(file.filename)[1].lower()

    language = None
    for lang, config in LANGUAGES.items():
        if ext in config['extensions']:
            language = lang
            break

    if not language:
        return jsonify({'error': f'Unsupported file type: {ext}'}), 400

    try:
        code = file.read().decode('utf-8')
    except UnicodeDecodeError:
        return jsonify({'error': 'Unable to decode file - ensure it is UTF-8'}), 400

    # Analyze the code
    rules = ANALYSIS_RULES.get(language, ANALYSIS_RULES.get('python', []))
    issues = []

    import re
    for rule in rules:
        flags = re.IGNORECASE if rule.get('case_insensitive', False) else 0
        pattern = rule['pattern']

        matches = re.finditer(pattern, code, flags)
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            if not any(i.get('line') == line_num and i['msg'] == rule['msg'] for i in issues):
                issues.append({
                    'type': rule['type'],
                    'msg': rule['msg'],
                    'line': line_num,
                    'match': match.group()[:50]
                })

    # Check long lines
    lines = code.split('\n')
    for i, line in enumerate(lines, 1):
        if len(line) > 120:
            issues.append({
                'type': 'style',
                'msg': f'Line too long ({len(line)} chars)',
                'line': i
            })

    # Calculate score
    type_weights = {'error': 15, 'security': 15, 'warning': 8, 'style': 3, 'info': 1}
    score = 100 - sum(type_weights.get(i['type'], 5) for i in issues)
    score = max(0, score)

    return jsonify({
        'filename': file.filename,
        'language': language,
        'language_name': LANGUAGES.get(language, {}).get('name', language.capitalize()),
        'issues': issues,
        'score': score,
        'lines': len(lines)
    })


@app.route('/api/export', methods=['POST'])
def export_results():
    """Export analysis results as JSON"""
    data = request.json

    # Create downloadable JSON
    export_data = {
        'exported_at': datetime.now().isoformat(),
        'analysis': data
    }

    filepath = '/tmp/devflow_export.json'
    with open(filepath, 'w') as f:
        json.dump(export_data, f, indent=2)

    return send_file(filepath, as_attachment=True, download_name='devflow_analysis.json')


@app.route('/api/history', methods=['GET'])
def get_history():
    """Get analysis history"""
    return jsonify({
        'history': getattr(app, 'history', [])
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
