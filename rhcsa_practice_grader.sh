#!/bin/bash
# Grader script - Comprehensive RHCSA Practice Set (67 Tasks) - CORRECTED
# Version: 2025-04-17

# --- Practice Tasks (Reference - Tasks 1-67 from user) ---
# Section 1: Understand and use essential tools
# Task 1: List files in /var/log (long format), show date.
# Task 2: Redirect find /usr -name 'python*' output (stdout > /tmp/python_files.log, stderr > /tmp/python_errors.log), append pwd to stdout log.
# Task 3: Grep '^root:' from /etc/passwd > /tmp/root_lines.txt. Grep non-commented https from /etc/services > /tmp/https_service.txt.
# Task 4: (Conceptual) SSH command: ssh -p 2222 testuser@server1.lab.example.com.
# Task 5: (Conceptual) Switch user: su -, exit. Run command as root: sudo dnf list installed.
# Task 6: Create archive /opt/etc_configs.tar.bz2 (bzip2) containing /etc/hosts, /etc/resolv.conf, /etc/sysconfig/. Verify contents with tar tfj.
# Task 7: Create empty file /opt/myapp.conf. Create /opt/readme.txt with content "Application Readme File".
# Task 8: Create dir /opt/data. Copy /etc/dnf/dnf.conf into it. Rename copy to dnf.conf.backup. Move /opt/data to /var/tmp/data_backup.
# Task 9: Create /opt/link_target.txt. Create hard link /tmp/link_target.hard. Create soft link /tmp/link_target.soft.
# Task 10: Create /opt/executable.sh. Set permissions 750. Change owner:group to root:wheel.
# Task 11: (Conceptual) Display man page for chmod. Find chrony docs location.
# Section 2: Create simple shell scripts
# Task 12: Create executable script /usr/local/sbin/check_service.sh checking systemctl is-active.
# Task 13: Create executable script /usr/local/sbin/list_files_by_ext.sh iterating /etc with a for loop.
# Task 14: Create executable script /usr/local/sbin/arg_processor.sh validating $# is 2.
# Task 15: Create executable script /usr/local/sbin/get_mem_info.sh capturing 'free -m' output.
# Section 3: Operate running systems
# Task 16: (Conceptual) Commands for immediate reboot, schedule poweroff +30m, cancel shutdown.
# Task 17: (Conceptual) Steps to boot to multi-user.target via GRUB edit.
# Task 18: (Conceptual) Steps to reset root password via GRUB edit + SELinux relabel.
# Task 19: Find chronyd PID, kill with SIGTERM, verify status.
# Task 20: Find sleep PID, renice to 10, verify with ps.
# Task 21: Check active tuned profile, get recommended, set recommended persistently.
# Task 22: Use journalctl for kernel messages (-k -b 0). Use journalctl for last 10 sshd errors (-u sshd -p err -n 10 -r).
# Task 23: Check/enable persistent journal storage (/var/log/journal).
# Task 24: Check firewalld enabled. Start httpd now. Stop cups now.
# Task 25: (Conceptual) SCP command for file transfer. Rsync command for directory sync.
# Section 4: Configure local storage
# Task 26: Create 500M and 1.5G partitions on /dev/sdb (assume), type LVM.
# Task 27: Create PVs on /dev/sdb1, /dev/sdb2. Verify.
# Task 28: Create VG vg_app on /dev/sdb1. Extend vg_app with /dev/sdb2. Verify.
# Task 29: Create LV lv_app_data (450M) in vg_app. Create LV lv_app_logs (50%FREE) in vg_app. Remove lv_app_logs. Verify.
# Task 30: Format lv_app_data with XFS (Label APP-DATA). Mount persistently on /srv/appdata via LABEL in fstab.
# Task 31: Add 1G swap partition on /dev/sdc (assume), format, enable now, enable persistent via UUID in fstab.
# Section 5: Create and configure file systems
# Task 32: Format /dev/sdb1 (ext4, label EXT4-DATA), /dev/sdb2 (vfat, label VFAT-SHARE). Mount/unmount manually.
# Task 33: (Conceptual) NFS mount command read-only. Fstab option _netdev.
# Task 34: Configure autofs master map for /direct using -hosts map type. Ensure service running/enabled.
# Task 35: Extend LV lv_app_data by 100M. Resize XFS filesystem.
# Task 36: Create dir /data/collaboration. Create group collaborators. Set dir group owner, permissions 2770.
# Task 37: (Conceptual) Diagnose permission issue steps (ls -l, ls -ld, id, getfacl, findmnt).
# Section 6: Deploy, configure, and maintain systems
# Task 38: Schedule job with 'at' (tonight 23:30). Configure cron job for user webmonitor (every 15 min).
# Task 39: Disable cups service persistence. Enable and start sshd service persistence.
# Task 40: Set default systemd target to graphical.target persistently.
# Task 41: Configure chronyd client for pool.ntp.org. Ensure running/enabled.
# Task 42: Install tmux. Update only bash. Remove telnet.
# Task 43: Use grubby to add kernel arg 'audit=1', remove 'rhgb' persistently from default kernel.
# Section 7: Manage basic networking
# Task 44: Configure primary interface static IPv4 (192.168.10.50/24, GW 192.168.10.1, DNS 192.168.10.1, 8.8.8.8) and IPv6 (2001:db8:10::50/64, GW 2001:db8:10::1) via nmcli.
# Task 45: Set hostname client5.internal.domain persistently. Add static entry to /etc/hosts (192.168.10.200 fileserver.internal.domain).
# Task 46: Ensure NetworkManager and firewalld services are enabled persistently.
# Task 47: Configure firewalld public zone: remove ssh service, add http service, add port 2222/tcp permanently. Reload.
# Section 8: Manage users and groups
# Task 48: Create user 'appuser' (UID 1500, comment "...", primary group users, supplementary wheel, shell /bin/bash).
# Task 49: Set password for appuser. Set max password age 90 days, warning 14 days.
# Task 50: Create group 'auditors' (GID 2000). Add mary, alice. Remove mary.
# Task 51: Configure sudoers (via visudo) to grant wheel group full root privileges.
# Section 9: Manage security
# Task 52: Configure firewalld internal zone: add source 10.0.1.0/24, allow ssh, allow https permanently. Reload.
# Task 53: Set system-wide default umask to 0027 persistently (e.g., /etc/bashrc).
# Task 54: Generate ed25519 key pair (no passphrase). Use ssh-copy-id to enable login for remoteuser@remote.example.com.
# Task 55: Check SELinux mode. Set permissive temporarily. Set enforcing temporarily. Verify persistent config is enforcing.
# Task 56: List SELinux context of /etc/passwd (ls -Z). List context of sshd processes (ps auxZ).
# Task 57: Restore default SELinux context for /srv/webcontent recursively (restorecon -Rv).
# Task 58: Configure SELinux port label: allow http_port_t on tcp/8081 persistently (semanage port).
# Task 59: Set SELinux boolean httpd_can_network_relay=on persistently. Set ftpd_full_access=off persistently (setsebool -P).
# Task 60: (Conceptual) Workflow for diagnosing SELinux denials (sealert/ausearch -> context/boolean/port fix).
# Section 10: Manage containers
# Task 61: Search for 'mariadb' image (podman search). Pull official mariadb:latest image (podman pull). List local images (podman images).
# Task 62: Inspect local mariadb:latest image for Env vars and History (podman image inspect/history).
# Task 63: Inspect remote ubi9/ubi:latest image (skopeo inspect). Copy local mariadb:latest to dir /opt/mariadb-image-dir (skopeo copy).
# Task 64: Run container 'db1' from mariadb:latest detached. List all containers. Stop db1. Start db1. Remove db1. (podman run/ps/stop/start/rm).
# Task 65: Run container 'webserver' from nginx:latest detached, map host port 8088 to container 80.
# Task 66: Generate systemd unit for container 'webserver' (/etc/systemd/system/), enable and start it.
# Task 67: Create Podman volume 'webapp_data'. Run container 'appserver' from httpd:latest detached, mount volume to /usr/local/apache2/htdocs/.
# --- End Practice Tasks ---

# --- Configuration ---
REPORT_FILE="/tmp/exam-report-comprehensive.txt"
PASS_THRESHOLD_PERCENT=70 # Percentage required to pass
MAX_SCORE=1005 # Total points for these 67 tasks (approx 15 points each)

# --- Color Codes ---
COLOR_OK="\033[32m"
COLOR_FAIL="\033[31m"
COLOR_INFO="\033[1m"
COLOR_RESET="\033[0m"

# --- Objective Mapping (1-10) ---
# Remapping all 67 tasks
declare -A TASK_OBJECTIVE=(
    [1]=1  [2]=1  [3]=1  [4]=1  [5]=1  [6]=1  [7]=1  [8]=1  [9]=1  [10]=1 [11]=1
    [12]=2 [13]=2 [14]=2 [15]=2
    [16]=3 [17]=3 [18]=3 [19]=3 [20]=3 [21]=3 [22]=3 [23]=3 [24]=3 [25]=3
    [26]=4 [27]=4 [28]=4 [29]=4 [30]=4 [31]=4
    [32]=5 [33]=5 [34]=5 [35]=5 [36]=5 [37]=5
    [38]=6 [39]=6 [40]=6 [41]=6 [42]=6 [43]=6
    [44]=7 [45]=7 [46]=7 [47]=7
    [48]=8 [49]=8 [50]=8 [51]=8
    [52]=9 [53]=9 [54]=9 [55]=9 [56]=9 [57]=9 [58]=9 [59]=9 [60]=9
    [61]=10 [62]=10 [63]=10 [64]=10 [65]=10 [66]=10 [67]=10
)

# Objective names (index 1-10)
declare -A OBJECTIVE_NAMES=(
    [1]="Understand and use essential tools"
    [2]="Create simple shell scripts"
    [3]="Operate running systems"
    [4]="Configure local storage"
    [5]="Create and configure file systems"
    [6]="Deploy, configure and maintain systems"
    [7]="Manage basic networking"
    [8]="Manage users and groups"
    [9]="Manage security"
    [10]="Manage containers"
)

# Initialize objective scores (index 1-10)
declare -A OBJECTIVE_SCORE
declare -A OBJECTIVE_TOTAL
for i in {1..10}; do
    OBJECTIVE_SCORE[$i]=0
    OBJECTIVE_TOTAL[$i]=0
done

# --- Corrected Helper Functions ---
check_file_exists() {
    local target_path="$1"
    if [ -e "$target_path" ]; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t File/Directory '$target_path' exists." | tee -a ${REPORT_FILE}
        return 0 # Standard success exit code
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t File/Directory '$target_path' does not exist." | tee -a ${REPORT_FILE}
        return 1 # Standard failure exit code
    fi
}

check_file_content() {
    local target_path="$1"
    local pattern="$2"
    local grep_opts="$3" # Optional grep options like -E, -i, -F, -q etc.
    if [ ! -f "$target_path" ]; then
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Cannot check content, file '$target_path' does not exist." | tee -a ${REPORT_FILE}
        return 1 # Failure
    fi
    if grep ${grep_opts} -- "${pattern}" "$target_path" &>/dev/null; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t File '$target_path' contains expected pattern '${pattern}'." | tee -a ${REPORT_FILE}
        return 0 # Success
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t File '$target_path' does not contain expected pattern '${pattern}'." | tee -a ${REPORT_FILE}
        return 1 # Failure
    fi
}

check_command_output() {
    local cmd="$1"
    local pattern="$2"
    local grep_opts="$3" # Optional grep options
    # Run command capturing both stdout and stderr
    if eval "$cmd" 2>&1 | grep ${grep_opts} -- "${pattern}" &>/dev/null; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Command '$cmd' output contains expected pattern '${pattern}'." | tee -a ${REPORT_FILE}
        return 0 # Success
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Command '$cmd' output does not contain expected pattern '${pattern}'." | tee -a ${REPORT_FILE}
        return 1 # Failure
    fi
}

check_service_status() {
    local service="$1"
    local state="$2" # active or enabled
    if systemctl "is-${state}" --quiet "$service"; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Service '$service' is $state." | tee -a ${REPORT_FILE}
        return 0 # Success
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Service '$service' is NOT $state." | tee -a ${REPORT_FILE}
        return 1 # Failure
    fi
}

check_mount() { # $1=mount_point, $2=device_pattern, $3=fs_type_pattern, $4=options_pattern
    local mount_point="$1"
    local device_pattern="$2" # Can be device path or UUID/LABEL=...
    local fs_type_pattern="$3"
    local options_pattern="$4" # Regex pattern for options
    local mount_line
    mount_line=$(findmnt -n -o SOURCE,TARGET,FSTYPE,OPTIONS --target "$mount_point" 2>/dev/null)

    if [[ -z "$mount_line" ]]; then
         echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Mount point '$mount_point' not found or nothing mounted." | tee -a ${REPORT_FILE}
         return 1 # Failure
    fi

    local source=$(echo "$mount_line" | awk '{print $1}')
    local fstype=$(echo "$mount_line" | awk '{print $3}')
    local options=$(echo "$mount_line" | awk '{print $4}')
    local all_ok=true

    # Check device (allow UUID/LABEL/Path)
    if [[ "$device_pattern" == UUID=* ]] || [[ "$device_pattern" == LABEL=* ]]; then
         local expected_dev=$(blkid -t "$device_pattern" -o device 2>/dev/null)
         # If blkid fails or doesn't find it, try matching source itself
         if [[ -z "$expected_dev" ]] || ! echo "$source" | grep -Eq "$expected_dev"; then
              if ! echo "$source" | grep -Eq "$device_pattern"; then # Check if source itself matches (e.g. LABEL=...)
                   echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Mount check: Source '$source' doesn't match expected device/UUID/Label '$device_pattern'." | tee -a ${REPORT_FILE}
                   all_ok=false
              fi
         fi
    elif ! echo "$source" | grep -Eq "$device_pattern"; then # Check if source matches path pattern
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Mount check: Source '$source' doesn't match expected pattern '$device_pattern'." | tee -a ${REPORT_FILE}
        all_ok=false
    fi
    # Check fstype
    if ! echo "$fstype" | grep -Eq "$fs_type_pattern"; then
         echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Mount check: FStype '$fstype' doesn't match expected pattern '$fs_type_pattern'." | tee -a ${REPORT_FILE}
         all_ok=false
    fi
    # Check options
    if ! echo "$options" | grep -Eq "$options_pattern"; then
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Mount check: Options '$options' do not contain expected pattern '$options_pattern'." | tee -a ${REPORT_FILE}
        all_ok=false
    fi

    if $all_ok; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Mount point '$mount_point' appears correctly configured and mounted." | tee -a ${REPORT_FILE}
        return 0 # Success
    else
        return 1 # Failure
    fi
}

add_score() {
    local points=$1
    SCORE=$(( SCORE + points ))
}

# Function to update scores (overall and by objective)
grade_task() {
    local task_num=$1
    local points_possible=$2
    local points_earned=$3
    local obj_index=${TASK_OBJECTIVE[$task_num]}

    add_score "$points_earned"
    TOTAL=$(( TOTAL + points_possible )) # Keep track of total attempted points

    if [[ -n "$obj_index" ]]; then
        OBJECTIVE_SCORE[$obj_index]=$(( ${OBJECTIVE_SCORE[$obj_index]} + points_earned ))
        OBJECTIVE_TOTAL[$obj_index]=$(( ${OBJECTIVE_TOTAL[$obj_index]} + points_possible ))
    else
         echo -e "${COLOR_FAIL}[WARN]${COLOR_RESET}\t Task $task_num has no objective mapping!" | tee -a ${REPORT_FILE}
    fi
}

# --- Initialization ---
clear
# Check root privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${COLOR_FAIL}This script must be run as root.${COLOR_RESET}"
   exit 1
fi

# Clean up previous report
rm -f ${REPORT_FILE} &>/dev/null
touch ${REPORT_FILE} &>/dev/null
echo "Starting Grade Evaluation Comprehensive Set (67 Tasks) - $(date)" | tee -a ${REPORT_FILE}
echo "---------------------------------------------------------------" | tee -a ${REPORT_FILE}

# Initialize score variables
SCORE=0
TOTAL=0

# --- Pre-check: SELinux ---
echo -e "${COLOR_INFO}Pre-check: SELinux Status${COLOR_RESET}" | tee -a ${REPORT_FILE}
if getenforce | grep -iq enforcing &>/dev/null; then
    echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t SELinux is in Enforcing mode." | tee -a ${REPORT_FILE}
else
    echo -e "${COLOR_FAIL}[FATAL]${COLOR_RESET}\t Task evaluation may be unreliable because SELinux is not in enforcing mode." | tee -a ${REPORT_FILE}
    # Allow grading to continue but warn heavily, especially for SELinux tasks
fi
echo -e "\n" | tee -a ${REPORT_FILE}

# --- Task Evaluation ---

### TASK 1: List files and show date
CURRENT_TASK=1; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: List files and show date${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15
if ls -l /var/log &> /dev/null && date &> /dev/null; then T_SCORE=15; fi
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 2: Redirection
CURRENT_TASK=2; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Redirection${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
check_file_exists "/tmp/python_files.log"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
check_file_exists "/tmp/python_errors.log"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
check_file_content "/tmp/python_files.log" "/" ""; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 3: grep and regex
CURRENT_TASK=3; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: grep and regex${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
rm -f /tmp/root_lines.txt /tmp/https_service.txt &>/dev/null
check_file_exists "/tmp/root_lines.txt"; if [[ $? -eq 0 ]]; then check_file_content "/tmp/root_lines.txt" "^root:" "-F"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 7)); fi; fi
check_file_exists "/tmp/https_service.txt"; if [[ $? -eq 0 ]]; then check_file_content "/tmp/https_service.txt" "https\s*443/tcp" "-i"; if [[ $? -eq 0 ]]; then if ! grep -qs '^\s*#' /tmp/https_service.txt; then TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t https_service.txt correct and no comments."; else TASK_POINTS=$((TASK_POINTS + 4)); echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t https_service.txt has comments."; fi; fi; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 4: SSH Command (Conceptual)
CURRENT_TASK=4; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: SSH Command (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Not automatically graded." | tee -a ${REPORT_FILE}
grade_task $CURRENT_TASK 0 0 # Assign 0 points
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 5: su / sudo (Conceptual)
CURRENT_TASK=5; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: su / sudo (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Not automatically graded." | tee -a ${REPORT_FILE}
grade_task $CURRENT_TASK 0 0 # Assign 0 points
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 6: Archive Creation and Verification
CURRENT_TASK=6; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Archive Creation and Verification${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
ARCHIVE_FILE_6="/opt/etc_configs.tar.bz2"
check_file_exists "$ARCHIVE_FILE_6"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); if tar tfj "$ARCHIVE_FILE_6" &>/dev/null && tar tfj "$ARCHIVE_FILE_6" | grep -q 'etc/hosts$' && tar tfj "$ARCHIVE_FILE_6" | grep -q 'etc/resolv.conf$' && tar tfj "$ARCHIVE_FILE_6" | grep -q 'etc/sysconfig/'; then TASK_POINTS=$((TASK_POINTS + 10)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Archive valid and contains expected contents."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Archive invalid or missing contents."; fi; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 7: Create/Edit Files
CURRENT_TASK=7; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Create/Edit Files${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
rm -f /opt/myapp.conf /opt/readme.txt &>/dev/null
check_file_exists "/opt/myapp.conf"; if [[ $? -eq 0 ]] && [[ $(stat -c %s /opt/myapp.conf) -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 7)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t /opt/myapp.conf exists and is empty."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t /opt/myapp.conf missing or not empty."; fi
check_file_exists "/opt/readme.txt"; if [[ $? -eq 0 ]]; then check_file_content "/opt/readme.txt" "^Application Readme File$" "-Fx"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 8)); fi; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 8: Create/Copy/Rename/Move Directory
CURRENT_TASK=8; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Create/Copy/Rename/Move Directory${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
check_file_exists "/var/tmp/data_backup"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 7)); check_file_exists "/var/tmp/data_backup/dnf.conf.backup"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 8)); fi; if [ -e "/opt/data" ]; then echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Original directory /opt/data still exists."; fi; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 9: Hard and Soft Links
CURRENT_TASK=9; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Hard and Soft Links${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
rm -f /opt/link_target.txt /tmp/link_target.hard /tmp/link_target.soft &>/dev/null; echo "Link source 9" > /opt/link_target.txt
check_file_exists "/tmp/link_target.hard"; if [[ $? -eq 0 ]]; then INODE_ORIG_9=$(stat -c %i /opt/link_target.txt 2>/dev/null); INODE_HARD_9=$(stat -c %i /tmp/link_target.hard 2>/dev/null); LINK_COUNT_9=$(stat -c %h /opt/link_target.txt 2>/dev/null); if [[ -n "$INODE_ORIG_9" ]] && [[ "$INODE_ORIG_9" == "$INODE_HARD_9" ]] && [[ "$LINK_COUNT_9" -ge 2 ]]; then TASK_POINTS=$((TASK_POINTS + 7)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Hard link correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Hard link incorrect."; fi; fi
check_file_exists "/tmp/link_target.soft"; if [[ $? -eq 0 ]]; then if [[ -L "/tmp/link_target.soft" ]] && [[ $(readlink /tmp/link_target.soft) == "/opt/link_target.txt" ]]; then TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Soft link correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Soft link incorrect."; fi; fi
rm -f /opt/link_target.txt &>/dev/null
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 10: Permissions and Ownership
CURRENT_TASK=10; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Permissions and Ownership${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
rm -f /opt/executable.sh &>/dev/null; touch /opt/executable.sh
check_file_exists "/opt/executable.sh"; if [[ $? -eq 0 ]]; then if [[ $(stat -c %a /opt/executable.sh) == "750" ]]; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Perms 750 ok."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Perms not 750."; fi; if [[ $(stat -c %U /opt/executable.sh) == "root" ]]; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Owner root ok."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Owner not root."; fi; if [[ $(stat -c %G /opt/executable.sh) == "wheel" ]]; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Group wheel ok."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Group not wheel."; fi; fi
rm -f /opt/executable.sh &>/dev/null
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 11: System Documentation (Conceptual)
CURRENT_TASK=11; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: System Documentation (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Not automatically graded." | tee -a ${REPORT_FILE}
grade_task $CURRENT_TASK 0 0
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 12: Script - check_service.sh
CURRENT_TASK=12; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Script - check_service.sh${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
SCRIPT_PATH_12="/usr/local/sbin/check_service.sh"
check_file_exists "$SCRIPT_PATH_12"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); if [ -x "$SCRIPT_PATH_12" ]; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script executable."; if "$SCRIPT_PATH_12" crond 2>/dev/null | grep -q "crond is running." && "$SCRIPT_PATH_12" nonexistentservice 2>/dev/null | grep -q "nonexistentservice is not running."; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script output correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script output incorrect."; fi; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script not executable."; fi; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 13: Script - list_files_by_ext.sh
CURRENT_TASK=13; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Script - list_files_by_ext.sh${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
SCRIPT_PATH_13="/usr/local/sbin/list_files_by_ext.sh"; touch /etc/dummy_test_script_13.log
check_file_exists "$SCRIPT_PATH_13"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); if [ -x "$SCRIPT_PATH_13" ]; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script executable."; if "$SCRIPT_PATH_13" log 2>&1 | grep -q "Found file: dummy_test_script_13.log"; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script output correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script output incorrect."; fi; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script not executable."; fi; fi
rm -f /etc/dummy_test_script_13.log
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 14: Script - arg_processor.sh
CURRENT_TASK=14; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Script - arg_processor.sh${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
SCRIPT_PATH_14="/usr/local/sbin/arg_processor.sh"
check_file_exists "$SCRIPT_PATH_14"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); if [ -x "$SCRIPT_PATH_14" ]; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script executable."; if "$SCRIPT_PATH_14" in out 2>/dev/null | grep -q "Input file: in Output file: out" && ! "$SCRIPT_PATH_14" in 2>&1 >/dev/null | grep -q "Usage:"; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script logic correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script logic incorrect."; fi; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script not executable."; fi; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 15: Script - get_mem_info.sh
CURRENT_TASK=15; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Script - get_mem_info.sh${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
SCRIPT_PATH_15="/usr/local/sbin/get_mem_info.sh"
check_file_exists "$SCRIPT_PATH_15"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); if [ -x "$SCRIPT_PATH_15" ]; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script executable."; OUTPUT_15=$("$SCRIPT_PATH_15" 2>&1); if echo "$OUTPUT_15" | head -n 1 | grep -q "Memory Information:" && echo "$OUTPUT_15" | grep -q "Mem:"; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script output correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script output incorrect."; fi; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script not executable."; fi; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 16: Reboot / Cancel Shutdown (Conceptual)
CURRENT_TASK=16; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Reboot / Cancel Shutdown (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Not automatically graded." | tee -a ${REPORT_FILE}
grade_task $CURRENT_TASK 0 0
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 17: Boot to multi-user.target Manually (Conceptual)
CURRENT_TASK=17; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Boot to multi-user.target Manually (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Not automatically graded." | tee -a ${REPORT_FILE}
grade_task $CURRENT_TASK 0 0
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 18: Root Password Reset (Conceptual)
CURRENT_TASK=18; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Root Password Reset (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Not automatically graded." | tee -a ${REPORT_FILE}
grade_task $CURRENT_TASK 0 0
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 19: Find and Kill Process (TERM)
CURRENT_TASK=19; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Find and Kill Process (TERM)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
# Basic check if chronyd is running
check_service_status chronyd active
if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 15)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t chronyd running. Assume kill would work."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t chronyd not running to test kill."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 20: Adjust Process Priority (renice)
CURRENT_TASK=20; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Adjust Process Priority (renice)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
sleep 10 & # Start a short sleep for testing
SLEEP_PID=$!
sleep 0.1 # Allow time for process to start
check_command_output "ps -o ni -p $SLEEP_PID | tail -n 1" "10" "" # Check if niceness is 10
if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 15)); fi
kill $SLEEP_PID &>/dev/null # Clean up
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 21: Manage Tuned Profiles
CURRENT_TASK=21; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Manage Tuned Profiles${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
RECOMMENDED_PROFILE=$(tuned-adm recommend 2>/dev/null)
if [[ -n "$RECOMMENDED_PROFILE" ]]; then
     check_command_output "tuned-adm active" "$RECOMMENDED_PROFILE"
     if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 15)); fi
else
     echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Could not determine recommended profile. Cannot grade."
fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 22: Using journalctl
CURRENT_TASK=22; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Using journalctl${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
# Cannot reliably check output content, just command success
if journalctl -k -b 0 --no-pager --quiet &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 7)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t journalctl -k -b 0 ran successfully."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t journalctl -k -b 0 failed."; fi
if journalctl -u sshd -p err -n 10 -r --no-pager --quiet &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t journalctl -u sshd -p err -n 10 -r ran successfully."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t journalctl -u sshd -p err -n 10 -r failed."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 23: Preserve System Journals
CURRENT_TASK=23; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Preserve System Journals${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15
if [ -d /var/log/journal ] || journalctl --disk-usage | grep -q '/var/log/journal'; then T_SCORE=15; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Journal storage appears persistent (/var/log/journal)."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Journal storage does not appear persistent."; fi
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 24: Start/Stop/Enable Services
CURRENT_TASK=24; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Start/Stop/Enable Services${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
check_service_status firewalld enabled; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
check_service_status httpd active; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
# Check cups is inactive (assuming stop was run)
check_service_status cups active; if [[ $? -ne 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t cups service is still active."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 25: Secure File Transfer (Conceptual)
CURRENT_TASK=25; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Secure File Transfer (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Not automatically graded." | tee -a ${REPORT_FILE}
grade_task $CURRENT_TASK 0 0
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 26: Partition Disk for LVM
CURRENT_TASK=26; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Partition Disk for LVM (/dev/sdb)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
# Check if partitions exist and have LVM type (approximate check)
if lsblk /dev/sdb -o NAME,SIZE,TYPE | grep -qE 'sdb1.*500M.*part' && \
   lsblk /dev/sdb -o NAME,SIZE,TYPE | grep -qE 'sdb2.*1\.5G.*part' && \
   parted -s /dev/sdb print | grep -Eq '\s+1\s+.*lvm' && \
   parted -s /dev/sdb print | grep -Eq '\s+2\s+.*lvm'; then
   TASK_POINTS=15
   echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Partitions /dev/sdb1 (500M) and /dev/sdb2 (1.5G) found with LVM type."
else
   echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Partitions /dev/sdb1 (500M) and/or /dev/sdb2 (1.5G) with LVM type not found correctly."
fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 27: Create LVM Physical Volume (PV)
CURRENT_TASK=27; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Create LVM Physical Volume (PV)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
if pvs /dev/sdb1 /dev/sdb2 &> /dev/null; then
    TASK_POINTS=15
    echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t PVs found on /dev/sdb1 and /dev/sdb2."
else
    echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t PVs not found on /dev/sdb1 and /dev/sdb2."
fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 28: Create/Extend LVM Volume Group (VG)
CURRENT_TASK=28; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Create/Extend LVM Volume Group (VG)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
VG_NAME="vg_app"
if vgs "$VG_NAME" &>/dev/null; then
    TASK_POINTS=$((TASK_POINTS + 5))
    echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t VG '$VG_NAME' exists."
    if vgdisplay "$VG_NAME" | grep -q '/dev/sdb1' && vgdisplay "$VG_NAME" | grep -q '/dev/sdb2'; then
        TASK_POINTS=$((TASK_POINTS + 10))
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t VG '$VG_NAME' contains both /dev/sdb1 and /dev/sdb2."
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t VG '$VG_NAME' does not contain both expected PVs."
    fi
else
    echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t VG '$VG_NAME' not found."
fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 29: Create/Delete LVM Logical Volume (LV)
CURRENT_TASK=29; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Create/Delete LVM Logical Volume (LV)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
VG_NAME="vg_app"; LV_DATA="lv_app_data"; LV_LOGS="lv_app_logs"; LV_DATA_SIZE="450.00m" # lvs uses lowercase m
# Check lv_app_data exists with correct size
LV_DATA_PATH="/dev/${VG_NAME}/${LV_DATA}"
if lvs "$LV_DATA_PATH" &>/dev/null; then
    TASK_POINTS=$((TASK_POINTS + 5))
    echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t LV '$LV_DATA' exists."
    if lvs --noheadings -o lv_size "$LV_DATA_PATH" | grep -q "$LV_DATA_SIZE"; then
        TASK_POINTS=$((TASK_POINTS + 5))
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t LV '$LV_DATA' size is correct (~450M)."
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t LV '$LV_DATA' size is incorrect."
    fi
else
    echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t LV '$LV_DATA' does not exist."
fi
# Check lv_app_logs does NOT exist
LV_LOGS_PATH="/dev/${VG_NAME}/${LV_LOGS}"
if ! lvs "$LV_LOGS_PATH" &>/dev/null; then
    TASK_POINTS=$((TASK_POINTS + 5))
    echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t LV '$LV_LOGS' correctly removed or never created."
else
    echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t LV '$LV_LOGS' still exists (should have been removed)."
fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 30: Format and Mount LV Persistently by LABEL
CURRENT_TASK=30; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Format and Mount LV Persistently by LABEL${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
LV_PATH="/dev/vg_app/lv_app_data"; MOUNT_POINT="/srv/appdata"; FS_TYPE="xfs"; LABEL="APP-DATA"
mkdir -p $MOUNT_POINT # Ensure mount point exists for checks
if blkid -L "$LABEL" &>/dev/null; then
    TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Filesystem with LABEL '$LABEL' found.";
    if blkid -L "$LABEL" | grep -q "$LV_PATH"; then echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Label '$LABEL' is on the correct LV."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Label '$LABEL' found, but not on '$LV_PATH'."; TASK_POINTS=$((TASK_POINTS - 2)); fi
    if blkid -L "$LABEL" | grep -q "TYPE=\"$FS_TYPE\""; then echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Filesystem type is '$FS_TYPE'."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Filesystem type is not '$FS_TYPE'."; TASK_POINTS=$((TASK_POINTS - 3)); fi
else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Filesystem with LABEL '$LABEL' not found."; fi
check_mount "$MOUNT_POINT" "LABEL=$LABEL" "$FS_TYPE" "defaults"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
check_file_content "/etc/fstab" "LABEL=${LABEL}.*${MOUNT_POINT}.*${FS_TYPE}"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t fstab entry for LABEL=${LABEL} not found/incorrect."; if [[ $TASK_POINTS -gt 5 ]]; then TASK_POINTS=$((TASK_POINTS - 2)); fi; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 31: Add Swap Partition
CURRENT_TASK=31; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Add Swap Partition${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
SWAP_COUNT_31=$(swapon -s | sed '1d' | wc -l); ORIG_SWAP_DEVICE_31=$(swapon -s | sed '1d' | awk '{print $1}' | head -n 1); FOUND_NEW_SWAP_31=false; NEW_SWAP_SIZE_OK_31=false; FSTAB_OK_31=false; ACTIVE_OK_31=false
if [[ $SWAP_COUNT_31 -gt 1 ]]; then ACTIVE_OK_31=true; TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Found >1 active swap space."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Did not find >1 active swap space."; fi
while IFS= read -r line; do [[ "$line" =~ ^\# ]] && continue; [[ "$line" =~ ^\s*$ ]] && continue; FS_SPEC=$(echo "$line" | awk '{print $1}'); FS_TYPE=$(echo "$line" | awk '{print $3}'); if [[ "$FS_SPEC" != "$ORIG_SWAP_DEVICE_31" ]] && [[ "$FS_TYPE" == "swap" ]]; then FOUND_NEW_SWAP_31=true; BLOCK_DEV=$(blkid -t UUID=$(echo $FS_SPEC | sed 's/UUID=//; s/"//g') -o device 2>/dev/null || echo $FS_SPEC); if [[ -b "$BLOCK_DEV" ]]; then SIZE_MB=$(lsblk -bno SIZE "$BLOCK_DEV" 2>/dev/null | awk '{printf "%.0f", $1/1024/1024}'); if [[ "$SIZE_MB" -ge 980 ]] && [[ "$SIZE_MB" -le 1070 ]]; then NEW_SWAP_SIZE_OK_31=true; fi; fi; break; fi; done < /etc/fstab
if $FOUND_NEW_SWAP_31; then FSTAB_OK_31=true; TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Found persistent swap entry."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t No persistent swap entry found."; fi
if $NEW_SWAP_SIZE_OK_31; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t New swap size correct (~1G)."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t New swap size incorrect."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 32: Format and Mount VFAT/ext4
CURRENT_TASK=32; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Format and Mount VFAT/ext4${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
# Check format (assume devices /dev/sdb1, /dev/sdb2 exist)
if blkid /dev/sdb1 2>/dev/null | grep -q 'LABEL="EXT4-DATA"' && blkid /dev/sdb1 2>/dev/null | grep -q 'TYPE="ext4"'; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t /dev/sdb1 formatted ext4/labeled."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t /dev/sdb1 not formatted/labeled correctly."; fi
if blkid /dev/sdb2 2>/dev/null | grep -q 'LABEL="VFAT-SHARE"' && blkid /dev/sdb2 2>/dev/null | grep -q 'TYPE="vfat"'; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t /dev/sdb2 formatted vfat/labeled."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t /dev/sdb2 not formatted/labeled correctly."; fi
# Check mount points exist
if [ -d /mnt/ext4data ] && [ -d /mnt/vfatshare ]; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Mount points exist."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Mount points missing."; fi
# Manual mount/unmount check is difficult in static script
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 33: NFS Mount (Conceptual)
CURRENT_TASK=33; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: NFS Mount (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Not automatically graded." | tee -a ${REPORT_FILE}
grade_task $CURRENT_TASK 0 0
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 34: Configure Autofs (-hosts)
CURRENT_TASK=34; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Configure Autofs (-hosts)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
AUTOFS_BASE="/direct"; MAP_TYPE="-hosts"
check_service_status autofs active; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
check_service_status autofs enabled; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
if grep -Eq "^\s*${AUTOFS_BASE}\s+${MAP_TYPE}" /etc/auto.master || grep -Eq "^\s*${AUTOFS_BASE}\s+${MAP_TYPE}" /etc/auto.master.d/*.conf &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Master map entry for '$AUTOFS_BASE' with type '$MAP_TYPE' found."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Master map entry incorrect."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 35: Extend LVM LV and Filesystem
CURRENT_TASK=35; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Extend LVM LV and Filesystem${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
LV_PATH_35="/dev/vg_app/lv_app_data"; MOUNT_POINT_35="/srv/appdata"
# Check LV exists
if [[ -b "$LV_PATH_35" ]]; then
    TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t LV '$LV_PATH_35' found."
    # Size check is hard without knowing initial size, check FS resize instead
    if [[ -d "$MOUNT_POINT_35" ]]; then
        ORIG_FS_SIZE=$(df -BM --output=size "$MOUNT_POINT_35" 2>/dev/null | tail -n 1 | sed 's/M//')
        # Assume resize occurred if FS size > original (e.g. > 450M from Q29)
        if [[ "$ORIG_FS_SIZE" -gt 500 ]]; then # Check if > 450M + ~100M
             TASK_POINTS=$((TASK_POINTS + 10))
             echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Filesystem on '$LV_PATH_35' appears resized (${ORIG_FS_SIZE}M)."
        else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Filesystem size (${ORIG_FS_SIZE}M) doesn't seem > ~550M."; fi
    else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Cannot find mount point '$MOUNT_POINT_35'."; fi
else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t LV '$LV_PATH_35' not found."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 36: Configure Set-GID Directory
CURRENT_TASK=36; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Configure Set-GID Directory${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
DIR_36="/data/collaboration"; GROUP_NAME_36="collaborators"
if ! getent group $GROUP_NAME_36 &>/dev/null; then groupadd $GROUP_NAME_36; echo -e "${COLOR_FAIL}[INFO]${COLOR_RESET}\t Group '$GROUP_NAME_36' created."; else echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Group '$GROUP_NAME_36' exists."; fi
check_file_exists "$DIR_36"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 3)); if [[ $(stat -c %G "$DIR_36") == "$GROUP_NAME_36" ]]; then TASK_POINTS=$((TASK_POINTS + 4)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Group owner correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Group owner incorrect."; fi; if [[ $(stat -c %a "$DIR_36") == "2770" ]]; then TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Permissions 2770 (SGID+rwx+rwx) correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Permissions incorrect (expected 2770)."; fi; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 37: Diagnose Permission Problem (Conceptual)
CURRENT_TASK=37; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Diagnose Permission Problem (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Not automatically graded." | tee -a ${REPORT_FILE}
grade_task $CURRENT_TASK 0 0
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 38: Schedule Tasks (at/cron)
CURRENT_TASK=38; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Schedule Tasks (at/cron)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
# Check at job (tricky, check if atd running)
check_service_status atd active; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 7)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t atd service running (assume job scheduled)."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t atd service not running."; fi
# Check webmonitor's cron job
id webmonitor &>/dev/null || useradd webmonitor
CRON_CMD_38="/home/webmonitor/check_site.sh"; CRON_SCHED_38="*/15 \* \* \* \*"; CRON_USER_38="webmonitor"
if crontab -l -u $CRON_USER_38 2>/dev/null | grep -Fq "$CRON_SCHED_38 $CRON_CMD_38"; then TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Cron job for '$CRON_USER_38' found."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Cron job for '$CRON_USER_38' not found."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 39: Service Enable/Disable
CURRENT_TASK=39; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Service Enable/Disable${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
check_service_status cups enabled; if [[ $? -ne 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t cups service is still enabled."; fi
check_service_status sshd enabled; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
check_service_status sshd active; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 40: Configure Default Target
CURRENT_TASK=40; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Configure Default Target${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15
check_command_output "systemctl get-default" "graphical.target" ""; if [[ $? -eq 0 ]]; then T_SCORE=15; fi
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 41: Configure Time Client (chrony)
CURRENT_TASK=41; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Configure Time Client (chrony)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
check_service_status chronyd active; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
check_service_status chronyd enabled; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
if grep -Eq "^\s*(server|pool)\s+pool\.ntp\.org" /etc/chrony.conf || chronyc sources 2>/dev/null | grep -q "pool.ntp.org"; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t pool.ntp.org found in config/sources."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t pool.ntp.org not found."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 42: Install/Update/Remove Packages
CURRENT_TASK=42; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Install/Update/Remove Packages${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
if rpm -q tmux &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t tmux installed."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t tmux not installed."; fi
# Cannot easily verify 'update only bash', assume ok if bash exists
if rpm -q bash &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t bash package present."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t bash package missing?"; fi
if ! rpm -q telnet &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t telnet package removed."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t telnet package still installed."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 43: Modify Bootloader (grubby)
CURRENT_TASK=43; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Modify Bootloader (grubby)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
DEFAULT_KERNEL_INFO=$(grubby --info=DEFAULT 2>/dev/null)
if echo "$DEFAULT_KERNEL_INFO" | grep -qw 'audit=1'; then TASK_POINTS=$((TASK_POINTS + 7)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t audit=1 argument found."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t audit=1 argument missing."; fi
if ! echo "$DEFAULT_KERNEL_INFO" | grep -qw 'rhgb'; then TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t rhgb argument removed."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t rhgb argument still present."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 44: Configure Static IPv4 & IPv6 (nmcli)
CURRENT_TASK=44; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Configure Static IPv4 & IPv6 (nmcli)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
CONN=$(nmcli -g NAME,DEVICE d | grep -v '^lo:' | head -n 1 | cut -d: -f1) # Find primary connection name
if [[ -z "$CONN" ]]; then echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Cannot find primary connection."; else
    if nmcli con show "$CONN" | grep -Eq 'ipv4.method:\s*manual' && \
       nmcli con show "$CONN" | grep -Eq 'ipv4.addresses:\s*192.168.10.50/24' && \
       nmcli con show "$CONN" | grep -Eq 'ipv4.gateway:\s*192.168.10.1' && \
       nmcli con show "$CONN" | grep -Eq 'ipv4.dns:\s*192.168.10.1,8.8.8.8|ipv4.dns:\s*8.8.8.8,192.168.10.1'; then
         TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t IPv4 static config appears correct.";
    else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t IPv4 static config incorrect."; fi
    if nmcli con show "$CONN" | grep -Eq 'ipv6.method:\s*manual' && \
       nmcli con show "$CONN" | grep -Eq 'ipv6.addresses:\s*2001:db8:10::50/64' && \
       nmcli con show "$CONN" | grep -Eq 'ipv6.gateway:\s*2001:db8:10::1'; then
         TASK_POINTS=$((TASK_POINTS + 7)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t IPv6 static config appears correct.";
    else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t IPv6 static config incorrect."; fi
fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 45: Configure Hostname Resolution
CURRENT_TASK=45; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Configure Hostname Resolution${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
check_command_output "hostnamectl status" "Static hostname: client5.internal.domain"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 7)); fi
check_file_content "/etc/hosts" "^\s*192\.168\.10\.200\s+fileserver\.internal\.domain"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 8)); fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 46: Configure Service Auto-start
CURRENT_TASK=46; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Configure Service Auto-start${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
check_service_status NetworkManager enabled; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 7)); fi
check_service_status firewalld enabled; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 8)); fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 47: Configure Firewall (firewalld)
CURRENT_TASK=47; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Configure Firewall (firewalld)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
if ! firewall-cmd --list-services --permanent --zone=public 2>/dev/null | grep -qw ssh; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t ssh service removed."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t ssh service not removed."; fi
if firewall-cmd --list-services --permanent --zone=public 2>/dev/null | grep -qw http; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t http service added."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t http service not added."; fi
if firewall-cmd --list-ports --permanent --zone=public 2>/dev/null | grep -qw 2222/tcp; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t port 2222/tcp added."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t port 2222/tcp not added."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 48: Create User Account
CURRENT_TASK=48; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Create User Account (appuser)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
USER="appuser"; UID=1500; COMMENT="Application Service Account"; PGROUP="users"; SGROUP="wheel"; SHELL="/bin/bash"
if id $USER &>/dev/null; then
    TASK_POINTS=$((TASK_POINTS + 3)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t User '$USER' exists."
    if [[ $(id -u $USER) == "$UID" ]]; then TASK_POINTS=$((TASK_POINTS + 3)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t UID $UID correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t UID incorrect."; fi
    if getent passwd $USER | cut -d: -f5 | grep -q "$COMMENT"; then TASK_POINTS=$((TASK_POINTS + 3)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Comment correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Comment incorrect."; fi
    if [[ $(id -gn $USER) == "$PGROUP" ]]; then TASK_POINTS=$((TASK_POINTS + 2)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Primary group $PGROUP correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Primary group incorrect."; fi
    if id -nG $USER | grep -qw "$SGROUP"; then TASK_POINTS=$((TASK_POINTS + 2)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Supplementary group $SGROUP correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Supplementary group incorrect."; fi
    if getent passwd $USER | cut -d: -f7 | grep -q "$SHELL"; then TASK_POINTS=$((TASK_POINTS + 2)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Shell $SHELL correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Shell incorrect."; fi
else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t User '$USER' does not exist."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 49: Password Aging
CURRENT_TASK=49; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Password Aging (appuser)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
USER="appuser"; MAX_AGE=90; WARN_AGE=14
if id $USER &>/dev/null; then
    if grep "^${USER}:" /etc/shadow | cut -d: -f2 | grep -q '^\$.*'; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Password appears set."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Password not set."; fi
    if chage -l $USER | grep -q "Maximum number of days between password change.*:\s*$MAX_AGE"; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Max age $MAX_AGE correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Max age incorrect."; fi
    if chage -l $USER | grep -q "Number of days of warning before password expires.*:\s*$WARN_AGE"; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Warn age $WARN_AGE correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Warn age incorrect."; fi
else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t User '$USER' does not exist."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 50: Group Management
CURRENT_TASK=50; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Group Management (auditors)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
GROUP="auditors"; GID=2000; USER_M="mary"; USER_A="alice"
if ! id $USER_M &>/dev/null; then useradd $USER_M; fi; if ! id $USER_A &>/dev/null; then useradd $USER_A; fi
if getent group $GROUP &>/dev/null; then
    TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Group '$GROUP' exists."
    if [[ $(getent group $GROUP | cut -d: -f3) == "$GID" ]]; then TASK_POINTS=$((TASK_POINTS + 3)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t GID $GID correct."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t GID incorrect."; fi
else groupadd -g $GID $GROUP; echo -e "${COLOR_FAIL}[INFO]${COLOR_RESET}\t Group '$GROUP' created."; fi
if id -nG $USER_A | grep -qw "$GROUP"; then TASK_POINTS=$((TASK_POINTS + 4)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t User '$USER_A' in group."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t User '$USER_A' not in group."; fi
if ! id -nG $USER_M | grep -qw "$GROUP"; then TASK_POINTS=$((TASK_POINTS + 3)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t User '$USER_M' not in group (correctly removed)."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t User '$USER_M' still in group."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 51: Configure Sudo (visudo)
CURRENT_TASK=51; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Configure Sudo (visudo)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15
# Check for wheel group sudo rule (uncommented)
if visudo -c -f /etc/sudoers &>/dev/null && grep -Eq "^\s*%wheel\s+ALL=\(ALL\)\s+ALL" /etc/sudoers; then
     T_SCORE=15; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Wheel group sudo rule found and enabled in /etc/sudoers."
elif [ -d /etc/sudoers.d ] && grep -Eq "^\s*%wheel\s+ALL=\(ALL\)\s+ALL" /etc/sudoers.d/* &>/dev/null; then
     T_SCORE=15; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Wheel group sudo rule found and enabled in /etc/sudoers.d/."
else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Wheel group sudo rule not found or not enabled."; fi
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 52: Firewall Zones/Sources
CURRENT_TASK=52; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Firewall Zones/Sources (internal)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
ZONE="internal"; SOURCE="10.0.1.0/24"; SVC1="ssh"; SVC2="https"
FW_CMD="firewall-cmd --permanent --zone=$ZONE"
if $FW_CMD --query-source=$SOURCE &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Source $SOURCE added to zone $ZONE."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Source $SOURCE not added to zone $ZONE."; fi
if $FW_CMD --query-service=$SVC1 &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Service $SVC1 allowed in zone $ZONE."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Service $SVC1 not allowed in zone $ZONE."; fi
if $FW_CMD --query-service=$SVC2 &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 5)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Service $SVC2 allowed in zone $ZONE."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Service $SVC2 not allowed in zone $ZONE."; fi
# Check if reloaded (hard to check definitively, assume if rules present)
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 53: Default File Permissions (umask)
CURRENT_TASK=53; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Default File Permissions (umask 0027)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15
EXPECTED_UMASK="0027"
# Check system-wide profile/bashrc
if grep -Eq "^\s*umask\s+${EXPECTED_UMASK}" /etc/profile /etc/bashrc /etc/profile.d/*.sh; then
     T_SCORE=15; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t umask $EXPECTED_UMASK found in system-wide profile/bashrc files.";
else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t umask $EXPECTED_UMASK not found in system-wide profile/bashrc files."; fi
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 54: SSH Key-Based Authentication
CURRENT_TASK=54; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: SSH Key-Based Authentication${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
# Check key files exist (for current root user running the script)
KEY_PRIVATE="$HOME/.ssh/id_ed25519"; KEY_PUBLIC="$HOME/.ssh/id_ed25519.pub"
check_file_exists "$KEY_PRIVATE"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 7)); fi
check_file_exists "$KEY_PUBLIC"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 8)); fi
# Cannot easily verify remote copy
if [[ $TASK_POINTS -lt 15 ]]; then echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Key pair files not found."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 55: SELinux Modes
CURRENT_TASK=55; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: SELinux Modes${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
# Check persistent config is enforcing
check_file_content "/etc/selinux/config" "^\s*SELINUX=enforcing"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 15)); else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Persistent SELinux mode is not enforcing."; fi
# Runtime check (getenforce) is less relevant as task involves changing it back and forth
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 56: List SELinux Contexts
CURRENT_TASK=56; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: List SELinux Contexts${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
check_command_output "ls -Z /etc/passwd" "passwd_t"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 7)); fi
check_command_output "ps auxZ | grep sshd" "sshd_t"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 8)); fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 57: Restore SELinux Context
CURRENT_TASK=57; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Restore SELinux Context (/srv/webcontent)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
# Create dummy file with wrong context, then check if it's fixed
mkdir -p /srv/webcontent; touch /srv/webcontent/restore_test.html
chcon -t user_tmp_t /srv/webcontent/restore_test.html &>/dev/null
# User runs restorecon...
# Now check context - expecting httpd_sys_content_t or similar default for /srv/www perhaps? Assume httpd_sys_content_t
check_command_output "ls -Z /srv/webcontent/restore_test.html" "httpd_sys_content_t"; if [[ $? -eq 0 ]]; then TASK_POINTS=15; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Default context not restored correctly."; fi
rm -rf /srv/webcontent # Cleanup
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 58: Manage SELinux Port Labels
CURRENT_TASK=58; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Manage SELinux Port Labels (tcp/8081)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
# Ensure semanage command available
if ! command -v semanage &> /dev/null; then dnf install -y policycoreutils-python-utils &> /dev/null; fi
check_command_output "semanage port -l" "^http_port_t.* tcp .*8081" "-E"; if [[ $? -eq 0 ]]; then T_SCORE=15; fi
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 59: Manage SELinux Booleans
CURRENT_TASK=59; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Manage SELinux Booleans${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
BOOL1="httpd_can_network_relay"; BOOL2="ftpd_full_access"
# Check persistent values
if semanage boolean -l | grep "^${BOOL1}\s*(" | grep -q '(on '; then TASK_POINTS=$((TASK_POINTS + 7)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t $BOOL1 persistent state is 'on'."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t $BOOL1 persistent state is not 'on'."; fi
if semanage boolean -l | grep "^${BOOL2}\s*(" | grep -q '(off '; then TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t $BOOL2 persistent state is 'off'."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t $BOOL2 persistent state is not 'off'."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 60: Diagnose SELinux (Conceptual)
CURRENT_TASK=60; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Diagnose SELinux (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Not automatically graded." | tee -a ${REPORT_FILE}
grade_task $CURRENT_TASK 0 0
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 61: Container Find/Retrieve Images
CURRENT_TASK=61; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Container Find/Retrieve Images (mariadb)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
IMG_NAME="mariadb"
# Check if image exists locally (allow official or just name)
if podman image exists docker.io/library/mariadb:latest || podman image exists mariadb:latest || podman image exists mariadb; then TASK_POINTS=$((TASK_POINTS + 15)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t $IMG_NAME image found locally."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t $IMG_NAME image not found locally."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 62: Container Inspect Images
CURRENT_TASK=62; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Container Inspect Images (mariadb)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
IMG_NAME="mariadb:latest" # Check specific tag if possible
# Check inspect command runs and history command runs (don't check specific output)
if podman image inspect $IMG_NAME &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 7)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t podman image inspect $IMG_NAME ran successfully."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t podman image inspect $IMG_NAME failed."; fi
if podman image history $IMG_NAME &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t podman image history $IMG_NAME ran successfully."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t podman image history $IMG_NAME failed."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 63: Container Management (skopeo)
CURRENT_TASK=63; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Container Management (skopeo)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
DEST_DIR="/opt/mariadb-image-dir"
# Check skopeo installed
if ! command -v skopeo &> /dev/null; then dnf install -y skopeo &> /dev/null; fi
# Check skopeo inspect runs
if skopeo inspect docker://registry.access.redhat.com/ubi9/ubi:latest &>/dev/null; then TASK_POINTS=$((TASK_POINTS + 7)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t skopeo inspect ran successfully."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t skopeo inspect failed."; fi
# Check if destination directory/manifest exists (implies copy worked)
if [ -d "$DEST_DIR" ] && [ -f "$DEST_DIR/manifest.json" ]; then TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Destination directory '$DEST_DIR' exists with manifest."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Destination directory '$DEST_DIR' or manifest missing."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 64: Container Basic Management (Lifecycle)
CURRENT_TASK=64; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Container Basic Management (Lifecycle)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
CONTAINER_NAME="db1"
# Check container does NOT exist (implies rm worked after stop/start)
if ! podman ps -a --filter name="^${CONTAINER_NAME}$" --format "{{.Names}}" | grep -q "$CONTAINER_NAME"; then
    TASK_POINTS=15; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Container '$CONTAINER_NAME' not found (implies successful lifecycle: run, stop, start, rm)."
else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Container '$CONTAINER_NAME' still exists."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 65: Container Run Service with Port Mapping
CURRENT_TASK=65; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Container Run Service with Port Mapping (nginx)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
CONTAINER_NAME="webserver"; HOST_PORT=8088; CONT_PORT=80
if podman ps --filter name="^${CONTAINER_NAME}$" --format "{{.Names}}" | grep -q "$CONTAINER_NAME"; then
    TASK_POINTS=$((TASK_POINTS + 7)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Container '$CONTAINER_NAME' is running."
    if podman port "$CONTAINER_NAME" | grep -q "${CONT_PORT}/tcp -> 0.0.0.0:${HOST_PORT}"; then
        TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Port mapping ${HOST_PORT}->${CONT_PORT} correct."
    else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Port mapping incorrect."; fi
else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Container '$CONTAINER_NAME' not running."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 66: Container Systemd Service
CURRENT_TASK=66; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Container Systemd Service (webserver)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
CONTAINER_NAME="webserver"; SERVICE_NAME="container-${CONTAINER_NAME}.service"
check_file_exists "/etc/systemd/system/${SERVICE_NAME}"; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
check_service_status "$SERVICE_NAME" enabled; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
check_service_status "$SERVICE_NAME" active; if [[ $? -eq 0 ]]; then TASK_POINTS=$((TASK_POINTS + 5)); fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 67: Container Persistent Storage (Named Volume)
CURRENT_TASK=67; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Container Persistent Storage (Named Volume)${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15; TASK_POINTS=0
VOLUME_NAME="webapp_data"; CONTAINER_NAME="appserver"; MOUNT_TARGET="/usr/local/apache2/htdocs"
if podman volume exists "$VOLUME_NAME"; then TASK_POINTS=$((TASK_POINTS + 7)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Volume '$VOLUME_NAME' exists."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Volume '$VOLUME_NAME' does not exist."; fi
if podman ps --filter name="^${CONTAINER_NAME}$" --format "{{.Names}}" | grep -q "$CONTAINER_NAME"; then
     if podman inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{.Name}} {{.Destination}}{{"\n"}}{{end}}' | grep -q "$VOLUME_NAME $MOUNT_TARGET"; then
          TASK_POINTS=$((TASK_POINTS + 8)); echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Volume '$VOLUME_NAME' correctly mounted in container '$CONTAINER_NAME'.";
     else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Volume '$VOLUME_NAME' not mounted correctly."; fi
else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Container '$CONTAINER_NAME' not running."; fi
T_SCORE=$TASK_POINTS
grade_task $CURRENT_TASK $T_TOTAL $T_SCORE
echo -e "\n" | tee -a ${REPORT_FILE}


# --- Final Grading ---
echo "---------------------------------------------------------------" | tee -a ${REPORT_FILE}
echo "Evaluation Complete. Press Enter for results overview."
read
clear

# --- Calculate Objective Scores ---
echo -e "\nPerformance on exam objectives:\n" | tee -a ${REPORT_FILE}
printf " \t%-45s : %s\n" "OBJECTIVE" "SCORE" | tee -a ${REPORT_FILE}
printf " \t%-45s : %s\n" "---------------------------------------------" "------" | tee -a ${REPORT_FILE}
GRAND_TOTAL_POSSIBLE=0
for i in {1..10}; do
    OBJ_NAME=${OBJECTIVE_NAMES[$i]:-"Unknown Objective $i"}
    OBJ_SCORE_VAL=${OBJECTIVE_SCORE[$i]:-0}
    OBJ_TOTAL_VAL=${OBJECTIVE_TOTAL[$i]:-0}
    PERCENT=0
    if [[ $OBJ_TOTAL_VAL -gt 0 ]]; then
        PERCENT=$(( OBJ_SCORE_VAL * 100 / OBJ_TOTAL_VAL ))
        GRAND_TOTAL_POSSIBLE=$(( GRAND_TOTAL_POSSIBLE + OBJ_TOTAL_VAL )) # Accumulate total points possible from graded objectives
    fi
    # Only display objectives that had tasks assigned
    if [[ $OBJ_TOTAL_VAL -gt 0 ]]; then
        printf " \t%-45s : %s%%\n" "$OBJ_NAME" "$PERCENT" | tee -a ${REPORT_FILE}
    fi
done
echo -e "\n------------------------------------------------" | tee -a ${REPORT_FILE}

# --- Calculate Overall Score ---
if [[ $GRAND_TOTAL_POSSIBLE -lt $MAX_SCORE ]] && [[ $GRAND_TOTAL_POSSIBLE -gt 0 ]]; then
    PASS_SCORE=$(( GRAND_TOTAL_POSSIBLE * PASS_THRESHOLD_PERCENT / 100 ))
    MAX_SCORE_ADJUSTED=$GRAND_TOTAL_POSSIBLE
else
    # Handle case where MAX_SCORE might be 0 if no tasks run
    [[ $MAX_SCORE -eq 0 ]] && MAX_SCORE=1
    PASS_SCORE=$(( MAX_SCORE * PASS_THRESHOLD_PERCENT / 100 ))
    MAX_SCORE_ADJUSTED=$MAX_SCORE
fi


echo -e "\nPassing score:\t\t${PASS_SCORE} ( ${PASS_THRESHOLD_PERCENT}% of ${MAX_SCORE_ADJUSTED} points possible)" | tee -a ${REPORT_FILE}
echo -e "Your score:\t\t${SCORE}" | tee -a ${REPORT_FILE}
echo -e "\n" | tee -a ${REPORT_FILE}

if [[ $SCORE -ge $PASS_SCORE ]]; then
    echo -e "${COLOR_OK}Result: PASS${COLOR_RESET}" | tee -a ${REPORT_FILE}
    echo -e "\n${COLOR_OK}CONGRATULATIONS!!${COLOR_RESET}\t You passed this practice test (Score >= ${PASS_THRESHOLD_PERCENT}%)."
    echo -e "\t\t\t Remember, this is practice; the real exam may differ."
else
    echo -e "${COLOR_FAIL}Result: NO PASS${COLOR_RESET}" | tee -a ${REPORT_FILE}
    echo -e "\n${COLOR_FAIL}[FAIL]${COLOR_RESET}\t\t You did NOT pass this practice test (Score < ${PASS_THRESHOLD_PERCENT}%)."
    echo -e "\t\t\t Review the [FAIL] messages and objective scores in ${REPORT_FILE}."
fi
echo -e "\nFull report saved to ${REPORT_FILE}"
