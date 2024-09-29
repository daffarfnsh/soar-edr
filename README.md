# soar-edr

LimaCharlie D&R Rule
'''
events:
  - NEW_PROCESS
  - EXISTING_PROCESS
op: and
rules:
  - op: is windows
  - op: or
    rules:
      - case sensitive: false
        op: ends with
        path: event/FILE_PATH
        value: LaZagne.exe
      - case sensitive: false
        op: contains
        path: event/COMMAND_LINE
        value: LaZagne
      - case sensitive: false
        op: is
        path: event/HASH
        value: 64dd55e1c2373deed25c2776f553c632e58c45e56a0e4639dfd54ee97eab9c19

- action: report
  metadata:
    author: Pep
    description: TEST - Detects Lazagne Usage
    falsepositives:
      - ToTheMoon
    level: high
    tags:
      - attack.credential_access
  name: Pep - HackTool - Lazagne
'''
