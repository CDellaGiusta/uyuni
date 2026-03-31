include:
  - channels

mgr_create_attestdir:
  file.directory:
    - name: /tmp/cocoattest
    - dir_mode: 700

mgr_inst_snpguest:
  pkg.latest:
    - pkgs:
      - snpguest
    - require:
      - sls: channels

mgr_write_request_data:
  cmd.run:
    - name: /usr/bin/echo "{{ salt['pillar.get']('attestation_data:nonce') }}" | /usr/bin/base64 -d > /tmp/cocoattest/random_user_nonce.bin
    - onlyif: /usr/bin/test -x /usr/bin/base64
    - require:
      - file: mgr_create_attestdir

mgr_create_snpguest_report:
  cmd.run:
    - name: /usr/bin/snpguest report /tmp/cocoattest/report.bin /tmp/cocoattest/random_user_nonce.bin
    - require:
      - cmd: mgr_write_request_data
      - file: mgr_create_attestdir

mgr_snpguest_report:
  cmd.run:
    - name: /usr/bin/cat /tmp/cocoattest/report.bin | /usr/bin/base64
    - require:
      - cmd: mgr_create_snpguest_report
      - file: mgr_create_attestdir

mgr_create_vlek_certificate:
  cmd.run:
    - name: /usr/bin/snpguest certificates PEM /tmp/cocoattest
    - require:
      - file: mgr_create_attestdir

mgr_vlek_certificate:
  cmd.run:
    - name: /usr/bin/cat /tmp/cocoattest/vlek.pem
    - require:
      - cmd: mgr_create_vlek_certificate
      - file: mgr_create_attestdir


