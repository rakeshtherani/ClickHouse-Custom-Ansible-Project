#!/bin/bash
# Complete ClickHouse Ansible Project Setup Script
# This script creates the folder structure and all necessary files for a ClickHouse Ansible project

# Define color codes for better readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}ClickHouse Ansible Project Setup${NC}"
echo -e "${YELLOW}This script will create and configure the complete ClickHouse Ansible project${NC}\n"

# Create base directory
mkdir -p clickhouse-ansible-with-all
cd clickhouse-ansible-with-all

# Create directory structure
echo -e "${YELLOW}Creating directory structure...${NC}"

# Create roles and templates directories
mkdir -p roles/common/tasks/clickhouse_keeper
mkdir -p roles/common/tasks/clickhouse_server
mkdir -p roles/clickhouse_server/{handlers,tasks,templates}
mkdir -p roles/clickhouse_keeper/{handlers,tasks,templates}
mkdir -p roles/common/templates/{schemas,schemas/views}
mkdir -p templates
mkdir -p group_vars

# Create main configuration files
echo -e "${YELLOW}Creating initial configuration files...${NC}"

# Create config.yml
cat > config.yml << 'EOF'
# config.yml
---
# Connection settings
clickhouse_user: "azureuser"
ssh_key_path: "~/.ssh/id_rsa"
server_ssh_key_path: "/home/azureuser/.ssh/id_rsa"
keeper_ssh_key_path: "/home/azureuser/.ssh/keeperkeys/id_rsa"

# ClickHouse version
clickhouse_version: "25.3.2.39"

# Cluster configuration
cluster_name: "clickhouse_cluster"
cluster_secret: "mysecretphrase"
shard_count: 1
replica_count: 3

# Network ports
keeper_port: 9181
keeper_raft_port: 9234
clickhouse_port: 9000
clickhouse_http_port: 8123

# Keeper and server nodes
keeper_ips:
  - "13.91.32.134"
  - "13.91.224.109"
  - "13.91.246.177"

server_ips:
  - "13.64.100.15"
  - "40.112.129.86"
  - "40.112.134.238"

# ClickHouse data paths
clickhouse_keeper_data_dir: "/opt/clickhouse"
clickhouse_keeper_log_dir: "/opt/clickhouse/log"
clickhouse_keeper_coordination_dir: "/opt/clickhouse/coordination"
clickhouse_keeper_log_level: "trace"

# Environment configuration
deployment_environment: "production"  # Options: development, testing, production

# Performance tuning
hardware_profile: "large"  # Options: small, medium, large, custom

# Security settings
ssl_enabled: true
password_complexity: "high"  # Options: low, medium, high
network_access: "10.0.0.0/8,127.0.0.1/32,::1/128"

# Monitoring settings
monitoring_enabled: true
prometheus_port: 9363

# Backup settings
backup_enabled: true
backup_retention_days: 30
remote_backup_enabled: true
s3_bucket: "clickhouse-backups"
s3_endpoint: "https://s3.amazonaws.com"
s3_path: "backups"

# Health check settings
health_checks_enabled: true

# Schema management
schema_management_enabled: true

# Vault settings
vault_enabled: true
vault_file: "vault/clickhouse_secrets.yml"
EOF

# Create setup_inventory.yml
cat > setup_inventory.yml << 'EOF'
# setup_inventory.yml
---
- name: Generate ClickHouse Inventory from Config
  hosts: localhost
  gather_facts: no
  vars_files:
    - config.yml

  tasks:
    - name: Calculate total nodes
      set_fact:
        total_nodes: "{{ shard_count|int * replica_count|int }}"

    - name: Set keeper count
      set_fact:
        keeper_count: "{{ keeper_ips | length }}"

    - name: Set hardware profile parameters
      set_fact:
        hw_profile_params:
          small:
            max_server_memory_usage_to_ram_ratio: 0.7
            max_server_memory_usage: 11000000000  # ~11GB
            background_pool_size: 4
            mark_cache_size: 2147483648  # 2GB
            uncompressed_cache_size: 2147483648  # 2GB
          medium:
            max_server_memory_usage_to_ram_ratio: 0.75
            max_server_memory_usage: 24000000000  # ~24GB
            background_pool_size: 8
            mark_cache_size: 4294967296  # 4GB
            uncompressed_cache_size: 4294967296  # 4GB
          large:
            max_server_memory_usage_to_ram_ratio: 0.8
            max_server_memory_usage: 51200000000  # ~51GB
            background_pool_size: 16
            mark_cache_size: 10737418240  # 10GB
            uncompressed_cache_size: 10737418240  # 10GB

    - name: Set current hardware profile
      set_fact:
        current_hw_profile: "{{ hw_profile_params[hardware_profile] }}"

    - name: Display configuration information
      debug:
        msg:
          - "ClickHouse Version: {{ clickhouse_version }}"
          - "Cluster Name: {{ cluster_name }}"
          - "Environment: {{ deployment_environment }}"
          - "Hardware Profile: {{ hardware_profile }}"
          - "Shards: {{ shard_count }} with {{ replica_count }} replicas each ({{ total_nodes }} total nodes)"
          - "Keeper Nodes: {{ keeper_count }}"
          - "SSL Enabled: {{ ssl_enabled }}"

    # Set default SSH key paths if not specified
    - name: Set default SSH key paths if not specified
      set_fact:
        server_ssh_key_path: "{{ server_ssh_key_path | default('/home/azureuser/.ssh/id_rsa') }}"
        keeper_ssh_key_path: "{{ keeper_ssh_key_path | default('/home/azureuser/.ssh/keeperkeys/id_rsa') }}"

    - name: Generate inventory file
      template:
        src: templates/inventory.j2
        dest: inventory.yml

    - name: Create group_vars directory
      file:
        path: group_vars
        state: directory

    - name: Generate all.yml in group_vars
      template:
        src: templates/all.yml.j2
        dest: group_vars/all.yml

    - name: Display next steps
      debug:
        msg:
          - "Inventory generated successfully!"
          - "You can now deploy your cluster with: ansible-playbook -i inventory.yml deploy_clickhouse.yml"
EOF

# Create deploy_clickhouse.yml
cat > deploy_clickhouse.yml << 'EOF'
---
- name: Deploy ClickHouse Keeper instances
  hosts: clickhouse_keepers
  become: true
  pre_tasks:
    - name: Include OS-specific configurations
      include_tasks: roles/common/tasks/install_pre_req.yml

    - name: Apply system optimizations
      include_tasks: roles/common/tasks/system_optimizations.yml
      when: deployment_environment is defined and deployment_environment == "production"
  handlers:
    - name: restart clickhouse-keeper
      systemd:
        name: clickhouse-keeper
        state: restarted
        daemon_reload: yes
  roles:
    - clickhouse_keeper
  post_tasks:
    - name: Configure SSL for Keeper
      include_tasks: roles/common/tasks/clickhouse_keeper/ssl_config.yml
      when: ssl_enabled | bool

    - name: Set up monitoring for Keeper
      include_tasks: roles/common/tasks/monitoring.yml
      when: monitoring_enabled | bool

    - name: Configure health checks for Keeper
      include_tasks: roles/common/tasks/health_checks.yml
      when: health_checks_enabled | bool

- name: Deploy ClickHouse Server instances
  hosts: clickhouse_servers
  become: true
  pre_tasks:
    - name: Include OS-specific configurations
      include_tasks: roles/common/tasks/install_pre_req.yml

    - name: Apply system optimizations
      include_tasks: roles/common/tasks/system_optimizations.yml
      when: deployment_environment is defined and deployment_environment == "production"
  handlers:
    - name: restart clickhouse-server
      systemd:
        name: clickhouse-server
        state: restarted
        daemon_reload: yes
      ignore_errors: yes
  roles:
    - clickhouse_server
  post_tasks:
    - name: Configure SSL for Server
      include_tasks: roles/common/tasks/clickhouse_server/ssl_config.yml
      when: ssl_enabled | bool

    - name: Configure users and security
      include_tasks: roles/common/tasks/clickhouse_server/security.yml

    - name: Set up backup configuration
      include_tasks: roles/common/tasks/clickhouse_server/backup_alt.yml
      when: backup_enabled | bool

    - name: Deploy schemas and tables
      include_tasks: roles/common/tasks/clickhouse_server/schema.yml
      when: schema_management_enabled | bool

    - name: Set up monitoring for Server
      include_tasks: roles/common/tasks/monitoring.yml
      when: monitoring_enabled | bool

    - name: Configure health checks for Server
      include_tasks: roles/common/tasks/health_checks.yml
      when: health_checks_enabled | bool

    - name: Verify cluster configuration
      include_tasks: roles/common/tasks/verify_cluster.yml
EOF

# Create template files
echo -e "${YELLOW}Creating template files...${NC}"

# Create templates/inventory.j2
mkdir -p templates
cat > templates/inventory.j2 << 'EOF'
---
all:
  vars:
    ansible_connection: ssh
    ansible_ssh_common_args: '-o StrictHostKeyChecking=no'
    ansible_become: yes
    ansible_become_method: sudo
    ansible_user: "{{ clickhouse_user }}"
  children:
    clickhouse_cluster:
      children:
        clickhouse_servers:
          hosts:
{% for i in range(total_nodes|int) %}
{% set current_shard = (i // replica_count|int) + 1 %}
{% set current_replica = (i % replica_count|int) + 1 %}
{% if i < server_ips|length %}
            clickhouse-s{{ '%02d' % current_shard }}-r{{ '%02d' % current_replica }}:
              ansible_host: {{ server_ips[i] }}
              ansible_ssh_private_key_file: "{{ server_ssh_key_path }}"
              shard: "{{ '%02d' % current_shard }}"
              replica: "{{ '%02d' % current_replica }}"
{% endif %}
{% endfor %}
        clickhouse_keepers:
          hosts:
{% for i in range(keeper_ips|length) %}
            clickhouse-keeper-{{ i + 1 }}:
              ansible_host: {{ keeper_ips[i] }}
              ansible_ssh_private_key_file: "{{ keeper_ssh_key_path }}"
              server_id: {{ i + 1 }}
{% endfor %}
EOF

# Create templates/all.yml.j2
cat > templates/all.yml.j2 << 'EOF'
---
# Common variables for all hosts
clickhouse_version: "{{ clickhouse_version }}"
clickhouse_keeper_version: "{{ clickhouse_version }}"

# Environment
deployment_environment: "{{ deployment_environment }}"
hardware_profile: "{{ hardware_profile }}"

# ClickHouse Keeper configuration
clickhouse_keeper_port: {{ keeper_port }}
clickhouse_keeper_raft_port: {{ keeper_raft_port }}
clickhouse_keeper_log_level: "{{ clickhouse_keeper_log_level }}"
clickhouse_keeper_data_dir: "{{ clickhouse_keeper_data_dir }}"
clickhouse_keeper_log_dir: "{{ clickhouse_keeper_log_dir }}"
clickhouse_keeper_coordination_dir: "{{ clickhouse_keeper_coordination_dir }}"

# ClickHouse Server configuration
clickhouse_server_port: {{ clickhouse_port }}
clickhouse_server_http_port: {{ clickhouse_http_port }}
clickhouse_cluster_name: "{{ cluster_name }}"
clickhouse_secret: "{{ cluster_secret }}"

# Hardware profile settings
max_server_memory_usage_to_ram_ratio: {{ current_hw_profile.max_server_memory_usage_to_ram_ratio }}
max_server_memory_usage: {{ current_hw_profile.max_server_memory_usage }}
background_pool_size: {{ current_hw_profile.background_pool_size }}
mark_cache_size: {{ current_hw_profile.mark_cache_size }}
uncompressed_cache_size: {{ current_hw_profile.uncompressed_cache_size }}

# Security settings
ssl_enabled: {{ ssl_enabled }}
password_complexity: "{{ password_complexity }}"
network_access: "{{ network_access }}"

# Monitoring settings
monitoring_enabled: {{ monitoring_enabled }}
prometheus_port: {{ prometheus_port }}

# Backup settings
backup_enabled: {{ backup_enabled }}
backup_retention_days: {{ backup_retention_days }}
remote_backup_enabled: {{ remote_backup_enabled }}
s3_bucket: "{{ s3_bucket }}"
s3_endpoint: "{{ s3_endpoint }}"
s3_path: "{{ s3_path }}"

# Health check settings
health_checks_enabled: {{ health_checks_enabled }}

# Schema management
schema_management_enabled: {{ schema_management_enabled }}

# Keeper IPs list for zookeeper configuration
clickhouse_keeper_hosts:
{% for ip in keeper_ips %}
  - host: "{{ ip }}"
    port: {{ keeper_port }}
{% endfor %}
EOF

# Create common task files
echo -e "${YELLOW}Creating common task files...${NC}"

# Create roles/common/tasks/main.yml
cat > roles/common/tasks/main.yml << 'EOF'
---
- name: Install required packages
  package:
    name:
      - ca-certificates
      - gnupg
      - apt-transport-https
      - curl
      - wget
      - netcat
    state: present
    update_cache: yes
  ignore_errors: yes
EOF

# Create roles/common/tasks/install_pre_req.yml
cat > roles/common/tasks/install_pre_req.yml << 'EOF'
---
- name: Install required packages
  package:
    name:
      - ca-certificates
      - gnupg
      - apt-transport-https
      - curl
      - wget
      - netcat
    state: present
    update_cache: yes
  when: ansible_os_family == "Debian"
  ignore_errors: yes

- name: Install required packages for RedHat based systems
  package:
    name:
      - ca-certificates
      - gnupg2
      - curl
      - wget
      - nc
    state: present
    update_cache: yes
  when: ansible_os_family == "RedHat"
  ignore_errors: yes

- name: Add ClickHouse GPG key for Debian
  apt_key:
    url: https://packages.clickhouse.com/gpg
    state: present
  when: ansible_os_family == "Debian"
  ignore_errors: yes

- name: Add ClickHouse repository for Debian
  apt_repository:
    repo: "deb https://packages.clickhouse.com/deb stable main"
    state: present
    filename: clickhouse
  when: ansible_os_family == "Debian"
  ignore_errors: yes

- name: Add ClickHouse repository for RedHat
  yum_repository:
    name: clickhouse
    description: ClickHouse Repository
    baseurl: https://packages.clickhouse.com/rpm/stable/
    gpgcheck: 0
    enabled: 1
  when: ansible_os_family == "RedHat"
  ignore_errors: yes
EOF

# Create roles/common/tasks/system_optimizations.yml
cat > roles/common/tasks/system_optimizations.yml << 'EOF'
---
- name: Configure sysctl parameters for ClickHouse
  sysctl:
    name: "{{ item.name }}"
    value: "{{ item.value }}"
    state: present
    reload: yes
  with_items:
    - { name: "vm.swappiness", value: "0" }
    - { name: "vm.max_map_count", value: "1048576" }
    - { name: "net.core.somaxconn", value: "4096" }
    - { name: "net.ipv4.tcp_max_syn_backlog", value: "4096" }
    - { name: "net.core.netdev_max_backlog", value: "10000" }
    - { name: "net.ipv4.tcp_slow_start_after_idle", value: "0" }
    - { name: "net.ipv4.tcp_fin_timeout", value: "10" }
    - { name: "net.ipv4.tcp_keepalive_time", value: "60" }
    - { name: "net.ipv4.tcp_keepalive_intvl", value: "10" }
    - { name: "net.ipv4.tcp_keepalive_probes", value: "6" }
    - { name: "fs.file-max", value: "9223372036854775807" }
    - { name: "fs.aio-max-nr", value: "1048576" }

- name: Configure system limits for ClickHouse
  pam_limits:
    domain: clickhouse
    limit_type: "{{ item.type }}"
    limit_item: "{{ item.item }}"
    value: "{{ item.value }}"
  with_items:
    - { type: "soft", item: "nofile", value: "262144" }
    - { type: "hard", item: "nofile", value: "262144" }
    - { type: "soft", item: "nproc", value: "131072" }
    - { type: "hard", item: "nproc", value: "131072" }

- name: Disable transparent huge pages
  shell: |
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
    echo never > /sys/kernel/mm/transparent_hugepage/defrag
  ignore_errors: yes

- name: Create systemd unit to disable transparent huge pages at boot
  copy:
    dest: /etc/systemd/system/disable-transparent-hugepages.service
    content: |
      [Unit]
      Description=Disable Transparent Huge Pages
      After=network.target

      [Service]
      Type=oneshot
      ExecStart=/bin/sh -c "echo never > /sys/kernel/mm/transparent_hugepage/enabled && echo never > /sys/kernel/mm/transparent_hugepage/defrag"
      RemainAfterExit=yes

      [Install]
      WantedBy=multi-user.target
    mode: 0644

- name: Enable the disable-transparent-hugepages service
  systemd:
    name: disable-transparent-hugepages
    enabled: yes
    daemon_reload: yes
    state: started
  ignore_errors: yes
EOF

# Create roles/common/tasks/monitoring.yml
cat > roles/common/tasks/monitoring.yml << 'EOF'
---
# Tasks only for ClickHouse Server nodes
- name: Ensure ClickHouse Server config directory exists
  file:
    path: "/etc/clickhouse-server/config.d"
    state: directory
    owner: clickhouse
    group: clickhouse
    mode: '0750'
  when: monitoring_enabled | bool and inventory_hostname in groups['clickhouse_servers']

- name: Configure Prometheus metrics for ClickHouse Server
  template:
    src: "{{ playbook_dir }}/roles/common/templates/prometheus.xml.j2"
    dest: "/etc/clickhouse-server/config.d/prometheus.xml"
    owner: clickhouse
    group: clickhouse
    mode: '0640'
  when: monitoring_enabled | bool and inventory_hostname in groups['clickhouse_servers']
  notify: restart clickhouse-server
  ignore_errors: yes

# Node Exporter for all nodes - first check if the package exists
- name: Check if prometheus-node-exporter package exists (RedHat)
  command: yum list prometheus-node-exporter
  register: node_exporter_package_exists
  failed_when: false
  changed_when: false
  when: monitoring_enabled | bool and ansible_os_family == "RedHat"

- name: Install Node Exporter from package (RedHat)
  yum:
    name: prometheus-node-exporter
    state: present
  when: monitoring_enabled | bool and ansible_os_family == "RedHat" and node_exporter_package_exists.rc == 0

- name: Install Node Exporter (Debian)
  apt:
    name: prometheus-node-exporter
    state: present
  when: monitoring_enabled | bool and ansible_os_family == "Debian"
  ignore_errors: yes

# Fallback manual installation of Node Exporter if package not available
- name: Install Node Exporter manually
  block:
    - name: Download Node Exporter
      get_url:
        url: "https://github.com/prometheus/node_exporter/releases/download/v1.6.0/node_exporter-1.6.0.linux-amd64.tar.gz"
        dest: "/tmp/node_exporter.tar.gz"

    - name: Extract Node Exporter
      unarchive:
        src: "/tmp/node_exporter.tar.gz"
        dest: "/tmp"
        remote_src: yes

    - name: Copy Node Exporter binary
      copy:
        src: "/tmp/node_exporter-1.6.0.linux-amd64/node_exporter"
        dest: "/usr/local/bin/node_exporter"
        mode: '0755'
        remote_src: yes

    - name: Create Node Exporter systemd service
      copy:
        dest: "/etc/systemd/system/node_exporter.service"
        content: |
          [Unit]
          Description=Node Exporter
          After=network.target

          [Service]
          Type=simple
          ExecStart=/usr/local/bin/node_exporter
          Restart=always

          [Install]
          WantedBy=multi-user.target
        mode: '0644'

    - name: Enable and start Node Exporter
      systemd:
        name: node_exporter
        enabled: yes
        state: started
        daemon_reload: yes
  when: >
    monitoring_enabled | bool and
    ((ansible_os_family == "RedHat" and node_exporter_package_exists.rc != 0) or
    (ansible_os_family == "Debian" and ansible_distribution != "Ubuntu"))
EOF

# Create roles/common/templates/prometheus.xml.j2
cat > roles/common/templates/prometheus.xml.j2 << 'EOF'
<clickhouse>
    <prometheus>
        <endpoint>/metrics</endpoint>
        <port>{{ prometheus_port }}</port>
        <metrics>true</metrics>
        <events>true</events>
        <asynchronous_metrics>true</asynchronous_metrics>
    </prometheus>
</clickhouse>
EOF

# Create roles/common/tasks/health_checks.yml
cat > roles/common/tasks/health_checks.yml << 'EOF'
---
# Health checks for ClickHouse Server
- name: Create health check scripts directory for Server
  file:
    path: "/etc/clickhouse-healthchecks"
    state: directory
    owner: clickhouse
    group: clickhouse
    mode: '0750'
  when: health_checks_enabled | bool and inventory_hostname in groups['clickhouse_servers']

- name: Install health check script for Server
  template:
    src: "{{ playbook_dir }}/roles/common/templates/clickhouse-healthcheck.sh.j2"
    dest: "/etc/clickhouse-healthchecks/clickhouse-healthcheck.sh"
    owner: clickhouse
    group: clickhouse
    mode: '0750'
  when: health_checks_enabled | bool and inventory_hostname in groups['clickhouse_servers']

- name: Create health check cron job for Server
  cron:
    name: "ClickHouse health check"
    user: clickhouse
    minute: "*/5"
    job: "/etc/clickhouse-healthchecks/clickhouse-healthcheck.sh | logger -t clickhouse-health"
    state: present
  when: health_checks_enabled | bool and inventory_hostname in groups['clickhouse_servers']

# Health checks for ClickHouse Keeper
- name: Create health check scripts directory for Keeper
  file:
    path: "/etc/clickhouse-keeper-healthchecks"
    state: directory
    owner: clickhouse
    group: clickhouse
    mode: '0750'
  when: health_checks_enabled | bool and inventory_hostname in groups['clickhouse_keepers']

- name: Install health check script for Keeper
  template:
    src: "{{ playbook_dir }}/roles/common/templates/clickhouse-keeper-healthcheck.sh.j2"
    dest: "/etc/clickhouse-keeper-healthchecks/clickhouse-keeper-healthcheck.sh"
    owner: clickhouse
    group: clickhouse
    mode: '0750'
  when: health_checks_enabled | bool and inventory_hostname in groups['clickhouse_keepers']

- name: Create health check cron job for Keeper
  cron:
    name: "ClickHouse Keeper health check"
    user: clickhouse
    minute: "*/5"
    job: "/etc/clickhouse-keeper-healthchecks/clickhouse-keeper-healthcheck.sh | logger -t clickhouse-keeper-health"
    state: present
  when: health_checks_enabled | bool and inventory_hostname in groups['clickhouse_keepers']
EOF

# Create health check script template for Server
cat > roles/common/templates/clickhouse-healthcheck.sh.j2 << 'EOF'
#!/bin/bash
# ClickHouse Server Health Check Script

# Check if ClickHouse server is running
if ! pgrep -x "clickhouse-server" > /dev/null; then
  echo "ERROR: ClickHouse server is not running!"
  exit 1
fi

# Check if we can connect to the server
if ! clickhouse-client --query "SELECT 1" &>/dev/null; then
  echo "ERROR: Cannot connect to ClickHouse server!"
  exit 1
fi

# Check server uptime
UPTIME=$(clickhouse-client --query "SELECT uptime()")
echo "ClickHouse server uptime: ${UPTIME} seconds"

# Check system.errors count
ERRORS=$(clickhouse-client --query "SELECT count() FROM system.errors")
if [ "$ERRORS" -gt 0 ]; then
  echo "WARNING: Found ${ERRORS} errors in system.errors table!"
else
  echo "No errors found in system.errors table"
fi

# Check system.metrics
MEM_USAGE=$(clickhouse-client --query "SELECT value FROM system.metrics WHERE metric='MemoryTracking'")
echo "Current memory usage: ${MEM_USAGE} bytes"

# Check system.disks
DISKS=$(clickhouse-client --query "SELECT name, free_space, total_space FROM system.disks FORMAT TSV")
echo "Disk space information:"
echo "${DISKS}"

# All checks passed
echo "Health check completed successfully"
exit 0
EOF

# Create health check script template for Keeper
cat > roles/common/templates/clickhouse-keeper-healthcheck.sh.j2 << 'EOF'
#!/bin/bash
# ClickHouse Keeper Health Check Script

# Check if ClickHouse Keeper is running
if ! pgrep -x "clickhouse-keeper" > /dev/null; then
  echo "ERROR: ClickHouse Keeper is not running!"
  exit 1
fi

# Check if we can connect to the Keeper
echo ruok | nc localhost {{ clickhouse_keeper_port }} > /dev/null
if [ $? -ne 0 ]; then
  echo "ERROR: Cannot connect to ClickHouse Keeper on port {{ clickhouse_keeper_port }}!"
  exit 1
fi

# Get Keeper stats
STATS=$(echo mntr | nc localhost {{ clickhouse_keeper_port }})
echo "ClickHouse Keeper stats:"
echo "$STATS"

# Check if Keeper is in leader or follower state
if echo "$STATS" | grep -q "leader"; then
  echo "This node is a LEADER"
elif echo "$STATS" | grep -q "follower"; then
  echo "This node is a FOLLOWER"
else
  echo "WARNING: Node is neither leader nor follower - cluster may be unstable"
fi

# Check log directory space
LOG_DIR_USAGE=$(df -h {{ clickhouse_keeper_coordination_dir }}/logs | tail -1 | awk '{print $5}')
echo "Log directory usage: $LOG_DIR_USAGE"

# All checks passed
echo "Health check completed successfully"
exit 0
EOF

# Create roles/common/tasks/verify_cluster.yml
cat > roles/common/tasks/verify_cluster.yml << 'EOF'
---
- name: Check cluster status
  shell: >
    clickhouse-client --query="SELECT
    cluster,
    shard_num,
    replica_num,
    host_name,
    host_address,
    port,
    is_local
    FROM system.clusters WHERE cluster = '{{ clickhouse_cluster_name }}'"
  register: cluster_status
  changed_when: false
  ignore_errors: yes

- name: Display cluster status
  debug:
    var: cluster_status.stdout_lines
  when: cluster_status is defined and cluster_status.stdout_lines is defined

- name: Check replication status
  shell: >
    clickhouse-client --query="SELECT
    database,
    table,
    is_leader,
    is_readonly,
    absolute_delay
    FROM system.replicas"
  register: replication_status
  changed_when: false
  ignore_errors: yes

- name: Display replication status
  debug:
    var: replication_status.stdout_lines
  when: replication_status is defined and replication_status.stdout_lines is defined
EOF

# Create clickhouse_keeper tasks files
echo -e "${BLUE}Creating clickhouse_keeper files...${NC}"

# Create roles/clickhouse_keeper/tasks/main.yml
cat > roles/clickhouse_keeper/tasks/main.yml << 'EOF'
---
- name: Install ClickHouse Keeper
  package:
    name: clickhouse-keeper
    state: present
  ignore_errors: yes

- name: Create ClickHouse directories
  file:
    path: "{{ item }}"
    state: directory
    mode: '0755'
    owner: clickhouse
    group: clickhouse
  loop:
    - "{{ clickhouse_keeper_data_dir }}"
    - "{{ clickhouse_keeper_log_dir }}"
    - "{{ clickhouse_keeper_coordination_dir }}/logs"
    - "{{ clickhouse_keeper_coordination_dir }}/snapshots"
  ignore_errors: yes

- name: Check if clickhouse user exists
  getent:
    database: passwd
    key: clickhouse
  ignore_errors: yes
  register: clickhouse_user_exists

- name: Create clickhouse user if not exists
  user:
    name: clickhouse
    system: yes
    create_home: no
    shell: /sbin/nologin
  when: clickhouse_user_exists is failed

- name: Configure ClickHouse Keeper
  template:
    src: keeper_config.xml.j2
    dest: /etc/clickhouse-keeper/keeper_config.xml
    mode: '0644'
  notify: restart clickhouse-keeper

- name: Create systemd service file for ClickHouse Keeper
  copy:
    dest: /etc/systemd/system/clickhouse-keeper.service
    content: |
      [Unit]
      Description=ClickHouse Keeper Server
      After=network.target

      [Service]
      Type=simple
      User=clickhouse
      Group=clickhouse
      ExecStart=/usr/bin/clickhouse-keeper --config=/etc/clickhouse-keeper/keeper_config.xml
      Restart=always
      RestartSec=30
      LimitCORE=infinity
      LimitNOFILE=500000

      [Install]
      WantedBy=multi-user.target
    mode: '0644'
  notify: restart clickhouse-keeper

- name: Enable and start ClickHouse Keeper service
  systemd:
    name: clickhouse-keeper
    enabled: yes
    state: started
    daemon_reload: yes
  check_mode: no

- name: Wait for ClickHouse Keeper to start
  wait_for:
    port: "{{ clickhouse_keeper_port }}"
    timeout: 120
    delay: 10
  ignore_errors: yes
  check_mode: no
EOF

# Create clickhouse_keeper handlers
cat > roles/clickhouse_keeper/handlers/main.yml << 'EOF'
---
- name: restart clickhouse-keeper
  systemd:
    name: clickhouse-keeper
    state: restarted
    daemon_reload: yes
EOF

# Create clickhouse_keeper templates
cat > roles/clickhouse_keeper/templates/keeper_config.xml.j2 << 'EOF'
<clickhouse>
    <logger>
        <level>{{ clickhouse_keeper_log_level }}</level>
        <log>{{ clickhouse_keeper_log_dir }}/clickhouse-keeper.log</log>
        <errorlog>{{ clickhouse_keeper_log_dir }}/clickhouse-keeper.err.log</errorlog>
        <size>1000M</size>
        <count>10</count>
    </logger>

    <max_connections>4096</max_connections>
    <listen_host>0.0.0.0</listen_host>
    <keeper_server>
            <tcp_port>{{ clickhouse_keeper_port }}</tcp_port>

            <!-- Must be unique among all keeper serves -->
            <server_id>{{ server_id }}</server_id>

            <log_storage_path>{{ clickhouse_keeper_coordination_dir }}/logs</log_storage_path>
            <snapshot_storage_path>{{ clickhouse_keeper_coordination_dir }}/snapshots</snapshot_storage_path>

            <coordination_settings>
                <operation_timeout_ms>10000</operation_timeout_ms>
                <min_session_timeout_ms>10000</min_session_timeout_ms>
                <session_timeout_ms>100000</session_timeout_ms>
                <raft_logs_level>information</raft_logs_level>
            </coordination_settings>

            <hostname_checks_enabled>true</hostname_checks_enabled>
            <raft_configuration>
                {% for host in groups['clickhouse_keepers'] %}
                <server>
                    <id>{{ hostvars[host].server_id }}</id>
                    <hostname>{{ hostvars[host].ansible_host }}</hostname>
                    <port>{{ clickhouse_keeper_raft_port }}</port>
                </server>
                {% endfor %}
            </raft_configuration>
    </keeper_server>

    <openSSL>
      <server>
            <certificateFile>/etc/clickhouse-keeper/server.crt</certificateFile>
            <privateKeyFile>/etc/clickhouse-keeper/server.key</privateKeyFile>
            <dhParamsFile>/etc/clickhouse-keeper/dhparam.pem</dhParamsFile>
            <verificationMode>none</verificationMode>
            <loadDefaultCAFile>true</loadDefaultCAFile>
            <cacheSessions>true</cacheSessions>
            <disableProtocols>sslv2,sslv3</disableProtocols>
            <preferServerCiphers>true</preferServerCiphers>
        </server>
    </openSSL>

</clickhouse>
EOF

# Create clickhouse_keeper SSL configuration
cat > roles/common/tasks/clickhouse_keeper/ssl_config.yml << 'EOF'
---
- name: Generate SSL certificates for ClickHouse Keeper
  shell: |
    openssl req -subj "/CN={{ inventory_hostname }}" -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout /etc/clickhouse-keeper/server.key -out /etc/clickhouse-keeper/server.crt
  args:
    creates: /etc/clickhouse-keeper/server.crt

- name: Generate DH params for ClickHouse Keeper
  shell: |
    openssl dhparam -out /etc/clickhouse-keeper/dhparam.pem 2048
  args:
    creates: /etc/clickhouse-keeper/dhparam.pem
EOF

# Create clickhouse_server files
echo -e "${BLUE}Creating clickhouse_server files...${NC}"

# Create roles/clickhouse_server/tasks/main.yml
cat > roles/clickhouse_server/tasks/main.yml << 'EOF'
---
- name: Create clickhouse user if not exists
  user:
    name: clickhouse
    system: yes
    create_home: no
    shell: /sbin/nologin

- name: Create ClickHouse directories
  file:
    path: "{{ item }}"
    state: directory
    mode: '0755'
    owner: clickhouse
    group: clickhouse
  loop:
    - "/var/lib/clickhouse"
    - "/var/log/clickhouse-server"
    - "/etc/clickhouse-server"
    - "/etc/clickhouse-server/config.d"

- name: Install ClickHouse packages
  package:
    name:
      - clickhouse-common-static
      - clickhouse-server
      - clickhouse-client
    state: present
  ignore_errors: yes

# Configure ClickHouse Server
- name: Ensure config.d directory exists
  file:
    path: /etc/clickhouse-server/config.d
    state: directory
    mode: '0755'
    owner: clickhouse
    group: clickhouse

- name: Configure ClickHouse Server display name
  template:
    src: config.xml.j2
    dest: /etc/clickhouse-server/config.d/config.xml
    mode: '0644'
    owner: clickhouse
    group: clickhouse
  notify: restart clickhouse-server

- name: Configure ClickHouse Server macros
  template:
    src: macros.xml.j2
    dest: /etc/clickhouse-server/config.d/macros.xml
    mode: '0644'
    owner: clickhouse
    group: clickhouse
  notify: restart clickhouse-server

- name: Configure ClickHouse Server remote servers
  template:
    src: remote-servers.xml.j2
    dest: /etc/clickhouse-server/config.d/remote-servers.xml
    mode: '0644'
    owner: clickhouse
    group: clickhouse
  notify: restart clickhouse-server

- name: Configure ClickHouse Server zookeeper connection
  template:
    src: use-keeper.xml.j2
    dest: /etc/clickhouse-server/config.d/use-keeper.xml
    mode: '0644'
    owner: clickhouse
    group: clickhouse
  notify: restart clickhouse-server

- name: Set ownership of config files
  file:
    path: "/etc/clickhouse-server"
    owner: clickhouse
    group: clickhouse
    recurse: yes

- name: Create systemd service file for ClickHouse Server
  copy:
    dest: /etc/systemd/system/clickhouse-server.service
    content: |
      [Unit]
      Description=ClickHouse Server
      After=network.target

      [Service]
      Type=simple
      User=clickhouse
      Group=clickhouse
      ExecStart=/usr/bin/clickhouse-server --config=/etc/clickhouse-server/config.xml
      Restart=always
      RestartSec=30
      LimitCORE=infinity
      LimitNOFILE=500000
      TimeoutStartSec=300

      [Install]
      WantedBy=multi-user.target
    mode: '0644'
  notify: restart clickhouse-server

- name: Enable and start ClickHouse Server service
  systemd:
    name: clickhouse-server
    enabled: yes
    state: started
    daemon_reload: yes
  check_mode: no

- name: Wait for ClickHouse Server to start
  wait_for:
    host: 127.0.0.1
    port: "{{ clickhouse_server_port }}"
    timeout: 120
    delay: 10
  register: wait_result
  ignore_errors: yes
  check_mode: no
EOF

# Create clickhouse_server handlers
cat > roles/clickhouse_server/handlers/main.yml << 'EOF'
---
- name: restart clickhouse-server
  systemd:
    name: clickhouse-server
    state: restarted
    daemon_reload: yes
  ignore_errors: yes
EOF

# Create clickhouse_server templates
cat > roles/clickhouse_server/templates/config.xml.j2 << 'EOF'
<clickhouse>
    <display_name>{{ hostvars[inventory_hostname].display_name | default(inventory_hostname) }}</display_name>
</clickhouse>
EOF

cat > roles/clickhouse_server/templates/macros.xml.j2 << 'EOF'
<clickhouse>
    <macros>
        <shard>{{ shard }}</shard>
        <replica>{{ replica }}</replica>
        <cluster>{{ clickhouse_cluster_name }}</cluster>
    </macros>
</clickhouse>
EOF

cat > roles/clickhouse_server/templates/remote-servers.xml.j2 << 'EOF'
<clickhouse>
    <remote_servers replace="true">
        <{{ clickhouse_cluster_name }}>
            <secret>{{ clickhouse_secret }}</secret>
            {% set ns = namespace(shard_hosts={}) %}

            {# Group servers by shard #}
            {% for host in groups['clickhouse_servers'] %}
                {% set shard_num = hostvars[host].shard | int %}
                {% if shard_num not in ns.shard_hosts %}
                    {% set ns.shard_hosts = ns.shard_hosts | combine({shard_num: []}) %}
                {% endif %}
                {% set _ = ns.shard_hosts[shard_num].append(host) %}
            {% endfor %}

            {# Create shards with proper replica configuration #}
            {% for shard_num, hosts in ns.shard_hosts.items() | sort %}
            <shard>
                <internal_replication>true</internal_replication>
                {% for host in hosts %}
                <replica>
                    <host>{{ hostvars[host].ansible_host }}</host>
                    <port>{{ clickhouse_server_port }}</port>
                </replica>
                {% endfor %}
            </shard>
            {% endfor %}
        </{{ clickhouse_cluster_name }}>
    </remote_servers>
</clickhouse>
EOF

cat > roles/clickhouse_server/templates/use-keeper.xml.j2 << 'EOF'
<clickhouse>
    <zookeeper>
        <!-- where are the ZK nodes -->
        {% for keeper in clickhouse_keeper_hosts %}
        <node>
            <host>{{ keeper.host }}</host>
            <port>{{ keeper.port }}</port>
        </node>
        {% endfor %}
    </zookeeper>
</clickhouse>
EOF

# Create server security files
cat > roles/common/tasks/clickhouse_server/security.yml << 'EOF'
---
- name: Ensure clickhouse config directory exists
  file:
    path: "{{ item }}"
    state: directory
    owner: clickhouse
    group: clickhouse
    mode: '0750'
  with_items:
    - "/etc/clickhouse-server/users.d"
    - "/etc/clickhouse-server/config.d"

- name: Configure ClickHouse users
  template:
    src: "{{ playbook_dir }}/roles/common/templates/users.xml.j2"
    dest: "/etc/clickhouse-server/users.d/users.xml"
    owner: clickhouse
    group: clickhouse
    mode: '0640'
  notify: restart clickhouse-server
EOF

# Create users template
cat > roles/common/templates/users.xml.j2 << 'EOF'
<clickhouse>
    <users>
        <default>
            <password></password>
            <networks>
                <ip>::/0</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
        </default>

        <admin>
            <password_sha256_hex>{{ admin_password_hash | default('8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92') }}</password_sha256_hex>
            <networks>
                <ip>0.0.0.0</ip>
            </networks>
            <profile>admin</profile>
            <quota>admin</quota>
        </admin>
    </users>

    <profiles>
        <default>
            <max_memory_usage>10000000000</max_memory_usage>
            <max_execution_time>60</max_execution_time>
            <max_rows_to_read>1000000000</max_rows_to_read>
            <max_bytes_to_read>10000000000</max_bytes_to_read>
            <max_result_rows>100000</max_result_rows>
            <max_result_bytes>100000000</max_result_bytes>
            <readonly>0</readonly>
        </default>

        <admin>
            <max_memory_usage>20000000000</max_memory_usage>
            <max_execution_time>180</max_execution_time>
            <max_rows_to_read>2000000000</max_rows_to_read>
            <max_bytes_to_read>20000000000</max_bytes_to_read>
            <max_result_rows>1000000</max_result_rows>
            <max_result_bytes>1000000000</max_result_bytes>
            <readonly>0</readonly>
        </admin>
    </profiles>

    <quotas>
        <default>
            <interval>
                <duration>3600</duration>
                <queries>100</queries>
                <errors>10</errors>
                <result_rows>10000</result_rows>
                <read_rows>1000000</read_rows>
                <execution_time>60</execution_time>
            </interval>
        </default>

        <admin>
            <interval>
                <duration>3600</duration>
                <queries>1000</queries>
                <errors>1000</errors>
                <result_rows>1000000</result_rows>
                <read_rows>10000000</read_rows>
                <execution_time>600</execution_time>
            </interval>
        </admin>
    </quotas>
</clickhouse>
EOF

# Create server SSL configuration
cat > roles/common/tasks/clickhouse_server/ssl_config.yml << 'EOF'
---
- name: Ensure SSL directories exist
  file:
    path: "/etc/clickhouse-server/ssl"
    state: directory
    owner: clickhouse
    group: clickhouse
    mode: '0750'

- name: Generate self-signed SSL certificate if not exists
  shell: |
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
      -subj "/C=US/ST=CA/L=SF/O=ClickHouse/CN={{ inventory_hostname }}" \
      -keyout /etc/clickhouse-server/ssl/server.key \
      -out /etc/clickhouse-server/ssl/server.crt
  args:
    creates: /etc/clickhouse-server/ssl/server.crt
  when: ssl_enabled | bool

- name: Generate DH parameters if not exists
  shell: openssl dhparam -out /etc/clickhouse-server/ssl/dhparam.pem 2048
  args:
    creates: /etc/clickhouse-server/ssl/dhparam.pem
  when: ssl_enabled | bool

- name: Configure ClickHouse SSL
  template:
    src: "{{ playbook_dir }}/roles/common/templates/ssl_config.xml.j2"
    dest: "/etc/clickhouse-server/config.d/ssl.xml"
    owner: clickhouse
    group: clickhouse
    mode: '0640'
  notify: restart clickhouse-server
  when: ssl_enabled | bool
EOF

# Create SSL configuration template
cat > roles/common/templates/ssl_config.xml.j2 << 'EOF'
<clickhouse>
    <openSSL>
        <server>
            <certificateFile>/etc/clickhouse-server/ssl/server.crt</certificateFile>
            <privateKeyFile>/etc/clickhouse-server/ssl/server.key</privateKeyFile>
            <dhParamsFile>/etc/clickhouse-server/ssl/dhparam.pem</dhParamsFile>
            <verificationMode>none</verificationMode>
            <loadDefaultCAFile>true</loadDefaultCAFile>
            <cacheSessions>true</cacheSessions>
            <disableProtocols>sslv2,sslv3</disableProtocols>
            <preferServerCiphers>true</preferServerCiphers>
        </server>
    </openSSL>

    <https_port>8443</https_port>
</clickhouse>
EOF

# Create backup configuration
cat > roles/common/tasks/clickhouse_server/backup_alt.yml << 'EOF'
---
- name: Check if clickhouse-backup is already installed
  stat:
    path: /usr/local/bin/clickhouse-backup
  register: backup_binary
  when: backup_enabled | bool

- name: Install clickhouse-backup (alternative method)
  block:
    - name: Download clickhouse-backup latest release
      get_url:
        url: "https://github.com/Altinity/clickhouse-backup/releases/latest/download/clickhouse-backup-linux-amd64.tar.gz"
        dest: "/tmp/clickhouse-backup.tar.gz"
      when: not backup_binary.stat.exists | default(false)

    - name: Create temporary directory for extraction
      file:
        path: /tmp/clickhouse-backup-extract
        state: directory
        mode: '0755'
      when: not backup_binary.stat.exists | default(false)

    - name: Extract clickhouse-backup
      unarchive:
        src: /tmp/clickhouse-backup.tar.gz
        dest: /tmp/clickhouse-backup-extract
        remote_src: yes
      when: not backup_binary.stat.exists | default(false)

    - name: Find clickhouse-backup binary
      find:
        paths: /tmp/clickhouse-backup-extract
        patterns: clickhouse-backup
        recurse: yes
      register: find_result
      when: not backup_binary.stat.exists | default(false)

    - name: Move clickhouse-backup binary
      copy:
        src: "{{ find_result.files[0].path }}"
        dest: "/usr/local/bin/clickhouse-backup"
        mode: '0755'
        remote_src: yes
      when: not backup_binary.stat.exists | default(false) and find_result.files is defined and find_result.files | length > 0
  when: backup_enabled | bool
  ignore_errors: yes

- name: Create backup directories
  file:
    path: "{{ item }}"
    state: directory
    owner: clickhouse
    group: clickhouse
    mode: '0750'
  with_items:
    - "/var/lib/clickhouse/backup"
    - "/etc/clickhouse-backup"
  when: backup_enabled | bool

- name: Configure clickhouse-backup
  template:
    src: "{{ playbook_dir }}/roles/common/templates/clickhouse-backup.yaml.j2"
    dest: "/etc/clickhouse-backup/config.yaml"
    owner: clickhouse
    group: clickhouse
    mode: '0640'
  when: backup_enabled | bool

- name: Create backup cron job
  cron:
    name: "ClickHouse backup"
    user: clickhouse
    hour: "1"
    minute: "0"
    job: "/usr/local/bin/clickhouse-backup create && {% if remote_backup_enabled | bool %}/usr/local/bin/clickhouse-backup upload{% endif %}"
    state: present
  when: backup_enabled | bool
EOF

# Create backup configuration template
cat > roles/common/templates/clickhouse-backup.yaml.j2 << 'EOF'
general:
  remote_storage: {{ "s3" if remote_backup_enabled else "none" }}
  max_file_size: 1073741824

clickhouse:
  host: localhost
  port: {{ clickhouse_server_port }}
  username: default
  password:
  data_path: /var/lib/clickhouse
  skip_tables: []
  timeout: 5m

backup:
  path: /var/lib/clickhouse/backup
  keep_local: {{ backup_retention_days }}

s3:
  access_key: {{ s3_access_key | default('') }}
  secret_key: {{ s3_secret_key | default('') }}
  bucket: {{ s3_bucket }}
  endpoint: {{ s3_endpoint }}
  path: {{ s3_path }}
  disable_ssl: false
  force_path_style: false
  keep: {{ backup_retention_days }}
EOF

# Create schema management
cat > roles/common/tasks/clickhouse_server/schema.yml << 'EOF'
---
- name: Ensure clickhouse-client is installed
  package:
    name: clickhouse-client
    state: present
  when: schema_management_enabled | bool

- name: Create databases
  shell: >
    clickhouse-client --query "CREATE DATABASE IF NOT EXISTS {{ item }} ENGINE = Atomic"
  with_items:
    - analytics
    - staging
    - reporting
  when: schema_management_enabled | bool
  ignore_errors: yes

- name: Create schema directory
  file:
    path: "/tmp/clickhouse-schema"
    state: directory
    mode: '0755'
  when: schema_management_enabled | bool

- name: Deploy table schema files
  template:
    src: "{{ playbook_dir }}/roles/common/templates/schemas/{{ item }}.sql.j2"
    dest: "/tmp/clickhouse-schema/{{ item }}.sql"
    mode: '0644'
  with_items:
    - analytics_events
    - analytics_events_distributed
  when: schema_management_enabled | bool
  ignore_errors: yes

- name: Apply table schemas
  shell: "clickhouse-client < /tmp/clickhouse-schema/{{ item }}.sql"
  with_items:
    - analytics_events
    - analytics_events_distributed
  when: schema_management_enabled | bool
  ignore_errors: yes
EOF

# Create schema templates
mkdir -p roles/common/templates/schemas
cat > roles/common/templates/schemas/analytics_events.sql.j2 << 'EOF'
CREATE TABLE IF NOT EXISTS analytics.events
(
    event_date Date,
    event_time DateTime,
    event_type String,
    user_id String,
    session_id String,
    properties String
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/analytics.events', '{replica}')
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, event_type, user_id);
EOF

cat > roles/common/templates/schemas/analytics_events_distributed.sql.j2 << 'EOF'
CREATE TABLE IF NOT EXISTS analytics.events_distributed
(
    event_date Date,
    event_time DateTime,
    event_type String,
    user_id String,
    session_id String,
    properties String
)
ENGINE = Distributed('{{ clickhouse_cluster_name }}', 'analytics', 'events', rand());
EOF

# Create README.md
echo -e "${YELLOW}Creating README.md...${NC}"
cat > README.md << 'EOF'
# ClickHouse Ansible Deployment Project

This Ansible project automates the deployment of a ClickHouse cluster with ClickHouse Keeper for coordination.

## Project Structure

```
clickhouse-ansible/
├── config.yml                  # Central configuration file
├── inventory.yml               # Generated inventory file
├── deploy_clickhouse.yml       # Main deployment playbook
├── setup_inventory.yml         # Inventory generator playbook
├── group_vars/                 # Group variables
│   └── all.yml                 # Common variables (generated)
├── roles/
│   ├── common/                 # Common setup tasks
│   │   └── tasks/
│   │       ├── main.yml
│   │       ├── install_pre_req.yml
│   │       ├── clickhouse_keeper/
│   │       └── clickhouse_server/
│   ├── clickhouse_server/      # Server role
│   │   ├── handlers/
│   │   ├── tasks/
│   │   └── templates/
│   └── clickhouse_keeper/      # Keeper role
│       ├── handlers/
│       ├── tasks/
│       └── templates/
└── templates/                  # Templates for generators
    ├── inventory.j2
    └── all.yml.j2
```

## Deployment Process

### Step 1: Generate the Inventory

```bash
ansible-playbook -i localhost, setup_inventory.yml -c local
```

This processes the config.yml file and generates:
* inventory.yml with all servers and their roles
* group_vars/all.yml with common variables

### Step 2: Deploy the Cluster

```bash
ansible-playbook -i inventory.yml deploy_clickhouse.yml
```

This playbook deploys both Keeper and Server components to their respective nodes.

## Configuration

Edit the `config.yml` file to customize your deployment:

* Connection settings (SSH users, keys)
* ClickHouse version
* Cluster configuration (shards, replicas)
* Node IPs for Keeper and Server
* Security settings
* Monitoring and backup settings
* And more...

## Features

This deployment includes:

### Monitoring
- ClickHouse metrics exposed via Prometheus endpoint
- Node Exporter installed on all nodes for system metrics
- Healthchecks for both Keeper and Server nodes

### Security
- SSL/TLS encryption
- User management with security profiles
- Network access control

### Backup
- Automated backups with clickhouse-backup
- S3 compatible remote storage support
- Configurable retention periods

### Performance Tuning
- System optimizations for performance
- Hardware profile-based memory settings

## Troubleshooting

If you encounter issues during deployment:

1. Check logs: `/var/log/clickhouse-server/` and `/var/log/clickhouse-keeper/`
2. Verify connectivity between nodes
3. Ensure sufficient disk space (minimum 10GB recommended)
4. Check system limits with `ulimit -a` (file descriptors, etc.)
EOF

echo -e "${GREEN}ClickHouse Ansible Project Structure Created Successfully!${NC}"
echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Edit ${BLUE}config.yml${NC} to configure your cluster settings"
echo -e "2. Run ${BLUE}ansible-playbook -i localhost, setup_inventory.yml -c local${NC} to generate inventory"
echo -e "3. Run ${BLUE}ansible-playbook -i inventory.yml deploy_clickhouse.yml${NC} to deploy your cluster"
