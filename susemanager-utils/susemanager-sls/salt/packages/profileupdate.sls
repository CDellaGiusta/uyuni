packages:
  mgrcompat.module_run:
    - name: pkg.info_installed
    - kwargs: {
          attr: 'status,arch,epoch,version,release,install_date_time_t',
{%- if grains.get('__suse_reserved_pkg_all_versions_support', False) %}
          errors: report,
          all_versions: true
{%- else %}
          errors: report
{%- endif %}
      }
{% if grains['os_family'] == 'Suse' %}
products:
  mgrcompat.module_run:
    - name: pkg.list_products
{% elif grains['os_family'] == 'RedHat' %}
{% include 'packages/redhatproductinfo.sls' %}
{% if grains['osmajorrelease'] >= 8 %}
modules:
  mgrcompat.module_run:
    - name: appstreams.get_enabled_modules
{% endif %}
{% elif grains['os_family'] == 'Debian' %}
debianrelease:
  cmd.run:
    - name: /usr/bin/cat /etc/os-release
    - onlyif: /usr/bin/test -f /etc/os-release
{% endif %}

include:
  - util.syncgrains
  - util.syncstates
  - util.syncmodules

grains_update:
  mgrcompat.module_run:
    - name: grains.items
    - require:
{%- if grains.get('__suse_reserved_saltutil_states_support', False) %}
      - saltutil: sync_grains
{%- else %}
      - mgrcompat: sync_grains
{%- endif %}

{% if not pillar.get('imagename') %}

status_uptime:
  mgrcompat.module_run:
    - name: status.uptime

{%- if not grains.get('transactional', False) %}
reboot_required:
  mgrcompat.module_run:
    - name: reboot_info.reboot_required
    {%- if grains['os_family'] == 'RedHat' and grains['osmajorrelease'] < 8 %}
    - onlyif:
      - which needs-restarting
    {%- endif %}
{%- endif %}

kernel_live_version:
  mgrcompat.module_run:
    - name: sumautil.get_kernel_live_version
    - require:
{%- if grains.get('__suse_reserved_saltutil_states_support', False) %}
      - saltutil: sync_modules
{%- else %}
      - mgrcompat: sync_modules
{%- endif %}
{% endif %}
