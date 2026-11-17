with open('static/js/netghost.js', encoding='utf-8') as f:
    content = f.read()
    lines = content.splitlines()

checks = {
    'messageRecovered flag declared': 'let messageRecovered = false' in content,
    'resetChecklist clears flag': ('messageRecovered = false' in content and 'resetChecklist' in content),
    'Decryption failed guarded': "msg.includes('Decryption failed') && !messageRecovered" in content,
    'message event sets flag (SSE)': ("data.type === 'message'" in content and content.count('messageRecovered = true') >= 1),
    'rx_auth_status FAILED guarded': '} else if (!messageRecovered)' in content,
    'rx_message_recovered sets flag': ('rx_message_recovered' in content and 'messageRecovered = true' in content),
}

all_ok = True
for name, ok in checks.items():
    status = 'OK' if ok else 'MISSING'
    if not ok:
        all_ok = False
    print(f'  {status}: {name}')

print()
print('ALL CHECKS PASSED' if all_ok else 'SOME CHECKS FAILED')
