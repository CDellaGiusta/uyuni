include:
  - channels

mgr_create_attestdir:
  file.directory:
    - name: /tmp/cocoattest
    - dir_mode: 700


{% if salt['pillar.get']('attestation_data:environment_type', 'NONE') in ['KVM_AMD_EPYC_MILAN','KVM_AMD_EPYC_GENOA','KVM_AMD_EPYC_BERGAMO','KVM_AMD_EPYC_SIENA','KVM_AMD_EPYC_TURIN'] %}

amd_epyc_snpguest_request:
  cmd.run:
    - name: /usr/bin/touch /tmp/cocoattest/amd.bin
    - require:
      - file: mgr_create_attestdir

{% endif %}


{% if salt['pillar.get']('attestation_data:environment_type', 'NONE') in ['KVM_IBM_Z'] %}

ibm_z_pvattest_request:
  cmd.run:
    - name: /usr/bin/touch /tmp/cocoattest/ibm.bin
    - require:
      - file: mgr_create_attestdir

{% endif %}


{% if salt['pillar.get']('attestation_data:environment_type', 'NONE') in ['KVM_AMD_EPYC_MILAN','KVM_AMD_EPYC_GENOA','KVM_AMD_EPYC_BERGAMO','KVM_AMD_EPYC_SIENA','KVM_AMD_EPYC_TURIN'] %}

secure_boot:
  cmd.run:
    - name: /usr/bin/touch /tmp/cocoattest/secure_boot.bin
    - require:
      - file: mgr_create_attestdir

{% endif %}


test_environment_type:
  cmd.run:
    - name: /usr/bin/touch /tmp/cocoattest/test_1_{{ salt['pillar.get']('attestation_data:environment_type', 'NONE') }}.bin
    - require:
      - file: mgr_create_attestdir


{% for result_type in salt['pillar.get']('attestation_data:result_types', []) %}
test_result_type_{{ result_type }}:
  cmd.run:
    - name: /usr/bin/touch /tmp/cocoattest/result_type_{{ result_type }}.txt
    - require:
      - file: mgr_create_attestdir
{% endfor %}




