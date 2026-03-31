include:
  - channels

mgr_create_attestdir:
  file.directory:
    - name: /tmp/cocoattest
    - dir_mode: 700


{% for result_type in salt['pillar.get']('attestation_data:result_types', []) %}

{%- if result_type == 'SEV_SNP' %}
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

{% endif %}

{%- if result_type == 'IBM_PVATTEST' %}
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

mgr_create_pvattest_report:
  cmd.run:
    - name: /usr/bin/pvattest perform -i /tmp/cocoattest/attestation_request.bin -o /tmp/cocoattest/attestation_report.bin -u /tmp/cocoattest/random_user_nonce.bin
    - require:
      - cmd: mgr_write_attestation_request
      - cmd: mgr_write_random_user_nonce
      - file: mgr_create_attestdir

mgr_pvattest_report:
  cmd.run:
    - name: /usr/bin/cat /tmp/cocoattest/attestation_report.bin | /usr/bin/base64
    - require:
      - cmd: mgr_create_pvattest_report
      - file: mgr_create_attestdir
{% endif %}

{%- if result_type  == 'SECURE_BOOT' %}
mgr_inst_mokutil:
  pkg.latest:
    - pkgs:
      - mokutil
    - require:
      - sls: channels

mgr_secureboot_enabled:
  cmd.run:
    - name: /usr/bin/mokutil --sb-state
    - success_retcodes:
      - 255
      - 0
{% endif %}

{% endfor %}


