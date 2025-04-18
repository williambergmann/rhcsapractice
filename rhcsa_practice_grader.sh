#!/bin/bash
# Grader script - Comprehensive RHCSA Practice Set
# Version: 2024-03-10

# --- Configuration ---
REPORT_FILE="/tmp/exam-report-comprehensive.txt"
PASS_THRESHOLD=70 # Percentage required to pass

# --- Color Codes ---
COLOR_OK="\033[32m"
COLOR_FAIL="\033[31m"
COLOR_INFO="\033[1m"
COLOR_RESET="\033[0m"
COLOR_AWESOME="\e[5m\033[32m"

# --- Helper Functions ---
# (Assume check_file_exists, check_file_content, check_command_output, add_score helpers from previous script exist here)
check_file_exists() {
    local target_path="$1"
    local points_ok="$2"
    local points_fail="$3"
    if [ -e "$target_path" ]; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t File/Directory '$target_path' exists." | tee -a ${REPORT_FILE}
        return $points_ok
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t File/Directory '$target_path' does not exist." | tee -a ${REPORT_FILE}
        return $points_fail
    fi
}

check_file_content() {
    local target_path="$1"
    local pattern="$2"
    local points_ok="$3"
    local points_fail="$4"
    local grep_opts="$5"
    if [ ! -f "$target_path" ]; then
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Cannot check content, file '$target_path' does not exist." | tee -a ${REPORT_FILE}
        return $points_fail
    fi
    # Use grep -E for extended regex if needed, otherwise basic grep
    if grep ${grep_opts} -- "${pattern}" "$target_path" &>/dev/null; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t File '$target_path' contains expected pattern '${pattern}'." | tee -a ${REPORT_FILE}
        return $points_ok
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t File '$target_path' does not contain expected pattern '${pattern}'." | tee -a ${REPORT_FILE}
        return $points_fail
    fi
}

check_command_output() {
    local cmd="$1"
    local pattern="$2"
    local points_ok="$3"
    local points_fail="$4"
    local grep_opts="$5"
    # Run command capturing both stdout and stderr to avoid breaking pipe if grep fails
    if eval "$cmd" 2>&1 | grep ${grep_opts} -- "${pattern}" &>/dev/null; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Command '$cmd' output contains expected pattern '${pattern}'." | tee -a ${REPORT_FILE}
        return $points_ok
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Command '$cmd' output does not contain expected pattern '${pattern}'." | tee -a ${REPORT_FILE}
        return $points_fail
    fi
}

add_score() {
    local points=$1
    SCORE=$(( SCORE + points ))
}

check_service_status() { # $1=service, $2=state (active|enabled), $3=points_ok, $4=points_fail
    local service="$1"
    local state="$2"
    local points_ok="$3"
    local points_fail="$4"
    if systemctl "is-${state}" --quiet "$service"; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Service '$service' is $state." | tee -a ${REPORT_FILE}
        return $points_ok
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Service '$service' is NOT $state." | tee -a ${REPORT_FILE}
        return $points_fail
    fi
}

check_mount() { # $1=mount_point, $2=device_pattern, $3=fs_type_pattern, $4=options_pattern, $5=points_ok, $6=points_fail
    local mount_point="$1"
    local device_pattern="$2" # Can be device path or UUID/LABEL=...
    local fs_type_pattern="$3"
    local options_pattern="$4" # Regex pattern for options
    local points_ok="$5"
    local points_fail="$6"
    local mount_line
    mount_line=$(findmnt -n -o SOURCE,TARGET,FSTYPE,OPTIONS --target "$mount_point")

    if [[ -z "$mount_line" ]]; then
         echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Mount point '$mount_point' not found or nothing mounted." | tee -a ${REPORT_FILE}
         return $points_fail
    fi

    local source=$(echo "$mount_line" | awk '{print $1}')
    local fstype=$(echo "$mount_line" | awk '{print $3}')
    local options=$(echo "$mount_line" | awk '{print $4}')

    local all_ok=true
    # Check device (allow UUID/LABEL/Path)
    if [[ "$device_pattern" == UUID=* ]] || [[ "$device_pattern" == LABEL=* ]]; then
         # Check UUID/LABEL source from blkid if possible
         local expected_dev=$(blkid -t "$device_pattern" -o device)
         if ! echo "$source" | grep -q "$expected_dev"; then
             echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Mounted source '$source' does not match expected device for '$device_pattern'." | tee -a ${REPORT_FILE}
              all_ok=false
         fi
    elif ! echo "$source" | grep -Eq "$device_pattern"; then # Check if source matches path pattern
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Mounted source '$source' does not match expected pattern '$device_pattern'." | tee -a ${REPORT_FILE}
        all_ok=false
    fi
    # Check fstype
    if ! echo "$fstype" | grep -Eq "$fs_type_pattern"; then
         echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Filesystem type '$fstype' does not match expected pattern '$fs_type_pattern'." | tee -a ${REPORT_FILE}
         all_ok=false
    fi
    # Check options
    if ! echo "$options" | grep -Eq "$options_pattern"; then
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Mount options '$options' do not contain expected pattern '$options_pattern'." | tee -a ${REPORT_FILE}
        all_ok=false
    fi

    if $all_ok; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Mount point '$mount_point' appears correctly configured and mounted." | tee -a ${REPORT_FILE}
        return $points_ok
    else
        return $points_fail
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
echo "Starting Grade Evaluation - Comprehensive Set - $(date)" | tee -a ${REPORT_FILE}
echo "----------------------------------------------------" | tee -a ${REPORT_FILE}

# Initialize score variables
SCORE=0
TOTAL=0
CURRENT_TASK=0

# --- Pre-check: SELinux ---
echo -e "${COLOR_INFO}Pre-check: SELinux Status${COLOR_RESET}" | tee -a ${REPORT_FILE}
if getenforce | grep -iq enforcing &>/dev/null; then
    echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t SELinux is in Enforcing mode." | tee -a ${REPORT_FILE}
else
    echo -e "${COLOR_FAIL}[FATAL]${COLOR_RESET}\t You will likely FAIL the exam because SELinux is not in enforcing mode. Set SELinux to enforcing mode ('setenforce 1' and check /etc/selinux/config) and try again." | tee -a ${REPORT_FILE}
    exit 666
fi
echo -e "\n" | tee -a ${REPORT_FILE}

# --- Task Evaluation ---

### TASK 1: ls and date
CURRENT_TASK=1; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: List files and show date${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=5
if ls -l /var/log &>/dev/null && date &>/dev/null; then
    echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Basic execution successful." | tee -a ${REPORT_FILE}
    add_score 5
else
     echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Basic command execution failed." | tee -a ${REPORT_FILE}
fi
TOTAL=$(( TOTAL + T_TOTAL )) # Score added directly by add_score
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 2: Redirection
CURRENT_TASK=2; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Redirection${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=10
rm -f /tmp/python_files.log /tmp/python_errors.log &>/dev/null
check_file_exists "/tmp/python_files.log" 3 0; add_score $?
check_file_exists "/tmp/python_errors.log" 3 0; add_score $?
# Check append worked (approx check: file is non-empty and modified recently)
if [ -s /tmp/python_files.log ] && [[ $(find /tmp/python_files.log -mmin -2 -print) ]]; then
    echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t /tmp/python_files.log seems to have content appended." | tee -a ${REPORT_FILE}
    add_score 4
else
    echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t /tmp/python_files.log missing or append check failed." | tee -a ${REPORT_FILE}
fi
TOTAL=$(( TOTAL + T_TOTAL ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 3: grep and regex
CURRENT_TASK=3; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: grep and regex${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=10
rm -f /tmp/root_lines.txt /tmp/https_service.txt &>/dev/null
check_file_exists "/tmp/root_lines.txt" 2 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 2 ]]; then check_file_content "/tmp/root_lines.txt" "^root:" 3 0 "-F"; add_score $?; fi
check_file_exists "/tmp/https_service.txt" 2 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 2 ]]; then
    check_file_content "/tmp/https_service.txt" "https\s*443/tcp" 3 0 "-i"; T_SUB_SCORE=$?
    add_score $T_SUB_SCORE
    if [[ $T_SUB_SCORE -eq 3 ]] && ! grep -qs '^\s*#' /tmp/https_service.txt; then
         echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t /tmp/https_service.txt does not contain commented lines." | tee -a ${REPORT_FILE}
    elif [[ $T_SUB_SCORE -eq 3 ]]; then
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t /tmp/https_service.txt appears to contain commented lines." | tee -a ${REPORT_FILE}
    fi
fi
TOTAL=$(( TOTAL + T_TOTAL ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 4: SSH Command (Conceptual)
CURRENT_TASK=4; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: SSH Command (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Grading skipped." | tee -a ${REPORT_FILE}
TOTAL=$(( TOTAL + 0 ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 5: su / sudo (Conceptual)
CURRENT_TASK=5; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: su / sudo (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Grading skipped." | tee -a ${REPORT_FILE}
TOTAL=$(( TOTAL + 0 ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 6: Archive Creation and Verification
CURRENT_TASK=6; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Archive Creation and Verification${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=10
ARCHIVE_FILE_6="/opt/etc_configs.tar.bz2"
check_file_exists "$ARCHIVE_FILE_6" 4 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 4 ]]; then
    if tar tfj "$ARCHIVE_FILE_6" &>/dev/null && \
       tar tfj "$ARCHIVE_FILE_6" | grep -q 'etc/hosts$' && \
       tar tfj "$ARCHIVE_FILE_6" | grep -q 'etc/resolv.conf$' && \
       tar tfj "$ARCHIVE_FILE_6" | grep -q 'etc/sysconfig/'; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Archive '$ARCHIVE_FILE_6' is valid bzip2 and contains expected contents." | tee -a ${REPORT_FILE}
        add_score 6
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Archive '$ARCHIVE_FILE_6' is not a valid bzip2 tarball or missing expected contents." | tee -a ${REPORT_FILE}
    fi
fi
TOTAL=$(( TOTAL + T_TOTAL ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 7: Create/Edit Files
CURRENT_TASK=7; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Create/Edit Files${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=10
rm -f /opt/myapp.conf /opt/readme.txt &>/dev/null
check_file_exists "/opt/myapp.conf" 2 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 2 ]] && [[ $(stat -c %s /opt/myapp.conf) -eq 0 ]]; then
    echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t /opt/myapp.conf exists and is empty." | tee -a ${REPORT_FILE}
    add_score 4
else
    echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t /opt/myapp.conf does not exist or is not empty." | tee -a ${REPORT_FILE}
fi
check_file_exists "/opt/readme.txt" 2 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 2 ]]; then
    check_file_content "/opt/readme.txt" "Application Readme File" 4 0 "-Fx"; add_score $?
fi
TOTAL=$(( TOTAL + T_TOTAL ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 8: Create/Copy/Rename/Move Directory
CURRENT_TASK=8; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Create/Copy/Rename/Move Directory${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=10
check_file_exists "/var/tmp/data_backup" 4 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 4 ]]; then
    check_file_exists "/var/tmp/data_backup/dnf.conf.backup" 6 0; add_score $?
    if [ ! -e "/opt/data" ]; then
         echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Original directory /opt/data was moved." | tee -a ${REPORT_FILE}
    else
         echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Original directory /opt/data still exists (should have been moved)." | tee -a ${REPORT_FILE}
    fi
fi
TOTAL=$(( TOTAL + T_TOTAL ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 9: Hard and Soft Links
CURRENT_TASK=9; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Hard and Soft Links${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=10
rm -f /opt/link_target.txt /tmp/link_target.hard /tmp/link_target.soft &>/dev/null
echo "Link source 9" > /opt/link_target.txt
check_file_exists "/tmp/link_target.hard" 2 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 2 ]]; then
    INODE_ORIG_9=$(stat -c %i /opt/link_target.txt)
    INODE_HARD_9=$(stat -c %i /tmp/link_target.hard)
    LINK_COUNT_9=$(stat -c %h /opt/link_target.txt)
    if [[ "$INODE_ORIG_9" == "$INODE_HARD_9" ]] && [[ "$LINK_COUNT_9" -ge 2 ]]; then
        echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t /tmp/link_target.hard appears to be a hard link." | tee -a ${REPORT_FILE}
        add_score 4
    else
        echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t /tmp/link_target.hard is not a correct hard link." | tee -a ${REPORT_FILE}
    fi
fi
check_file_exists "/tmp/link_target.soft" 2 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 2 ]]; then
    if [[ -L "/tmp/link_target.soft" ]] && [[ $(readlink /tmp/link_target.soft) == "/opt/link_target.txt" ]]; then
         echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t /tmp/link_target.soft is a symbolic link pointing to /opt/link_target.txt." | tee -a ${REPORT_FILE}
         add_score 4
    else
         echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t /tmp/link_target.soft is not a correct symbolic link." | tee -a ${REPORT_FILE}
    fi
fi
rm -f /opt/link_target.txt &>/dev/null # Clean up source
TOTAL=$(( TOTAL + T_TOTAL ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 10: Permissions and Ownership
CURRENT_TASK=10; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Permissions and Ownership${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=15
rm -f /opt/executable.sh &>/dev/null; touch /opt/executable.sh
PERMS_OCT_10=$(stat -c %a /opt/executable.sh)
if [[ "$PERMS_OCT_10" == "750" ]]; then add_score 5; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Permissions 750 set."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Permissions are $PERMS_OCT_10, expected 750."; fi
OWNER_10=$(stat -c %U /opt/executable.sh)
if [[ "$OWNER_10" == "root" ]]; then add_score 5; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Owner is root."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Owner is $OWNER_10, expected root."; fi
GROUP_10=$(stat -c %G /opt/executable.sh)
if [[ "$GROUP_10" == "wheel" ]]; then add_score 5; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Group is wheel."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Group is $GROUP_10, expected wheel."; fi
rm -f /opt/executable.sh &>/dev/null
TOTAL=$(( TOTAL + T_TOTAL ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 11: System Documentation (Conceptual)
CURRENT_TASK=11; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: System Documentation (Conceptual)${COLOR_RESET}" | tee -a ${REPORT_FILE}
echo -e "${COLOR_INFO}[INFO]${COLOR_RESET}\t Conceptual task. Grading skipped." | tee -a ${REPORT_FILE}
TOTAL=$(( TOTAL + 0 ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 12: Script - check_service.sh
CURRENT_TASK=12; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Script - check_service.sh${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=10
SCRIPT_PATH_12="/usr/local/sbin/check_service.sh"
check_file_exists "$SCRIPT_PATH_12" 2 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 2 ]]; then
    if [ -x "$SCRIPT_PATH_12" ]; then
        add_score 3; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script '$SCRIPT_PATH_12' is executable."
        # Test active
        systemctl start crond &>/dev/null
        if "$SCRIPT_PATH_12" crond 2>/dev/null | grep -q "crond is running."; then add_score 2; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script output correct for active service."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script output incorrect for active service."; fi
        # Test inactive
        systemctl stop crond &>/dev/null
         if "$SCRIPT_PATH_12" crond 2>/dev/null | grep -q "crond is not running."; then add_score 3; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script output correct for inactive service."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script output incorrect for inactive service."; fi
    else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script '$SCRIPT_PATH_12' is not executable."; fi
fi
TOTAL=$(( TOTAL + T_TOTAL ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 13: Script - list_files_by_ext.sh
CURRENT_TASK=13; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Script - list_files_by_ext.sh${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=10
SCRIPT_PATH_13="/usr/local/sbin/list_files_by_ext.sh"
touch /etc/dummy_test_script.log /etc/dummy_test_script.conf # Setup
check_file_exists "$SCRIPT_PATH_13" 2 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 2 ]]; then
     if [ -x "$SCRIPT_PATH_13" ]; then
          add_score 3; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script '$SCRIPT_PATH_13' is executable."
          OUTPUT_13_LOG=$("$SCRIPT_PATH_13" log 2>&1)
          OUTPUT_13_CONF=$("$SCRIPT_PATH_13" conf 2>&1)
          if echo "$OUTPUT_13_LOG" | grep -q "Found file: /etc/dummy_test_script.log" && echo "$OUTPUT_13_CONF" | grep -q "Found file: /etc/dummy_test_script.conf"; then
               echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script output correct for finding files by extension."
               add_score 5
          else
               echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script output incorrect. Output (log): $OUTPUT_13_LOG Output (conf): $OUTPUT_13_CONF"
          fi
     else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script '$SCRIPT_PATH_13' is not executable."; fi
fi
rm -f /etc/dummy_test_script.log /etc/dummy_test_script.conf # Cleanup
TOTAL=$(( TOTAL + T_TOTAL ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 14: Script - arg_processor.sh
CURRENT_TASK=14; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Script - arg_processor.sh${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=10
SCRIPT_PATH_14="/usr/local/sbin/arg_processor.sh"
check_file_exists "$SCRIPT_PATH_14" 2 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 2 ]]; then
     if [ -x "$SCRIPT_PATH_14" ]; then
          add_score 3; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script '$SCRIPT_PATH_14' is executable."
          # Test correct usage
          if "$SCRIPT_PATH_14" /tmp/in /tmp/out 2>/dev/null | grep -q "Processing files from /tmp/in to /tmp/out"; then add_score 2; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script output correct for valid arguments."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script output incorrect for valid arguments."; fi
          # Test incorrect usage (stderr check)
          ERR_OUTPUT=$("$SCRIPT_PATH_14" /tmp/in 2>&1 >/dev/null)
          ERR_STATUS=$?
          if [[ $ERR_STATUS -ne 0 ]] && echo "$ERR_OUTPUT" | grep -q "Usage: arg_processor.sh <source_dir> <destination_dir>"; then add_score 3; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script handles incorrect arguments correctly (stderr message and exit status)."; else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script did not handle incorrect arguments correctly."; fi
     else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script '$SCRIPT_PATH_14' is not executable."; fi
fi
TOTAL=$(( TOTAL + T_TOTAL ))
echo -e "\n" | tee -a ${REPORT_FILE}

### TASK 15: Script - get_mem_info.sh
CURRENT_TASK=15; echo -e "${COLOR_INFO}Evaluating Task $CURRENT_TASK: Script - get_mem_info.sh${COLOR_RESET}" | tee -a ${REPORT_FILE}
T_SCORE=0; T_TOTAL=10
SCRIPT_PATH_15="/usr/local/sbin/get_mem_info.sh"
check_file_exists "$SCRIPT_PATH_15" 2 0; T_SUB_SCORE=$?
if [[ $T_SUB_SCORE -eq 2 ]]; then
     if [ -x "$SCRIPT_PATH_15" ]; then
          add_score 3; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script '$SCRIPT_PATH_15' is executable."
          OUTPUT_15=$("$SCRIPT_PATH_15" 2>&1)
          if echo "$OUTPUT_15" | head -n 1 | grep -q "Memory Information:" && echo "$OUTPUT_15" | grep -q "Mem:"; then
               add_score 5; echo -e "${COLOR_OK}[OK]${COLOR_RESET}\t\t Script output contains header and 'free' command output.";
          else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script output incorrect. Output was:\n$OUTPUT_15"; fi
     else echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t Script '$SCRIPT_PATH_15' is not executable."; fi
fi
TOTAL=$(( TOTAL + T_TOTAL ))
echo -e "\n" | tee -a ${REPORT_FILE}


# --- Add Grading Blocks for Tasks 16 - 67 here ---
# --- Follow the pattern: Task Header, Variable Init, Checks, Add Score, Add Total, Newline ---
# --- Use helper functions or direct commands as appropriate ---

# Placeholder for remaining tasks
echo -e "${COLOR_INFO}INFO: Grading for tasks 16-67 not fully implemented in this example grader.${COLOR_RESET}" | tee -a ${REPORT_FILE}
# Add dummy points to avoid division by zero if no tasks implemented
if [[ $TOTAL -eq 0 ]]; then TOTAL=1; fi


# --- Final Grading ---
echo "----------------------------------------------------" | tee -a ${REPORT_FILE}
echo "Evaluation Complete. Press Enter for results overview."
read
clear
grep FAIL ${REPORT_FILE} &>/dev/null || echo -e "\nNo FAIL messages recorded." >> ${REPORT_FILE}
cat ${REPORT_FILE}
echo "Press Enter for final score."
read
clear
echo -e "\n"
echo -e "${COLOR_INFO}Your total score for this run is $SCORE out of a total of $TOTAL${COLOR_RESET}"

PASS_SCORE=$(( TOTAL * PASS_THRESHOLD / 100 ))

if [[ $TOTAL -gt 0 ]] && [[ $SCORE -ge $PASS_SCORE ]]; then
    echo -e "${COLOR_OK}CONGRATULATIONS!!${COLOR_RESET}\t You passed the implemented tasks (Score >= ${PASS_THRESHOLD}%)."
    echo -e "\t\t\t Remember, this is practice; the real exam may differ."
elif [[ $TOTAL -gt 0 ]]; then
    echo -e "${COLOR_FAIL}[FAIL]${COLOR_RESET}\t\t You did NOT pass the implemented tasks (Score < ${PASS_THRESHOLD}%)."
    echo -e "\t\t\t Review the [FAIL] messages in ${REPORT_FILE} and study the corresponding topics."
else
    echo -e "${COLOR_INFO}No tasks were graded for score.${COLOR_RESET}"
fi
echo -e "\nFull report saved to ${REPORT_FILE}"