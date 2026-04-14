include:
  - channels

mgr_create_attestdir:
  file.directory:
    - name: /tmp/cocoattest
    - dir_mode: 700

mgr_inst_pvattest:
  pkg.latest:
    - pkgs:
      - s390-tools
    - require:
      - sls: channels

mgr_write_attestation_request:
  cmd.run:
    - name: /usr/bin/echo "{{ salt['pillar.get']('attestation_data:attestation_request') }}" | /usr/bin/base64 -d > /tmp/cocoattest/attestation_request.bin
    - onlyif: /usr/bin/test -x /usr/bin/base64
    - require:
      - file: mgr_create_attestdir

mgr_write_random_user_nonce:
  cmd.run:
    - name: /usr/bin/echo "{{ salt['pillar.get']('attestation_data:nonce') }}" | /usr/bin/base64 -d > /tmp/cocoattest/random_user_nonce.bin
    - onlyif: /usr/bin/test -x /usr/bin/base64
    - require:
      - file: mgr_create_attestdir

mgr_create_pvattest_response:
  cmd.run:
    - name: /usr/bin/pvattest perform -i /tmp/cocoattest/attestation_request.bin -o /tmp/cocoattest/response.bin -u /tmp/cocoattest/random_user_nonce.bin
    - require:
      - cmd: mgr_write_attestation_request
      - cmd: mgr_write_random_user_nonce
      - file: mgr_create_attestdir

mgr_pvattest_response:
  cmd.run:
    - name: /usr/bin/cat /tmp/cocoattest/response.bin | /usr/bin/base64
    - require:
      - cmd: mgr_create_pvattest_response
      - file: mgr_create_attestdir

mgr_cleanup_attest:
  file.absent:
    - name: /tmp/cocoattest
    - require:
      - file: mgr_create_attestdir
