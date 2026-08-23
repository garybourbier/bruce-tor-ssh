#!/usr/bin/env bash
# torssh-menu.sh — menu à choix pour piloter le T-Embed (Bruce-TorSSH) via Tor.
# Chaque choix exécute une commande sur le .onion (mini-shell + CLI Bruce).
#
# Usage:   ./torssh-menu.sh [onion] [user]
# Exemple: ./torssh-menu.sh ubtpn2...did.onion bruce
#
# Le compte "bruce" accepte n'importe quel mot de passe. Installe sshpass pour
# ne pas le retaper à chaque commande :  sudo pacman -S sshpass
set -u

ONION="${1:-ubtpn2yryf3yhg7vgt3owbo5idv54xkiwxlulud43ajiuufkvbkzniid.onion}"
USER_SSH="${2:-bruce}"
PORT=22
PC_IP="${PC_IP:-10.69.112.86}"   # cible par défaut pour le jump host

have() { command -v "$1" >/dev/null 2>&1; }

# --- Exécute une ligne de commande sur le T-Embed via Tor -----------------------
# On pipe "cmd\nexit\n" dans le shell distant : il exécute puis ferme la session.
run_remote() {
    local cmd="$1"
    echo ">>> $cmd"
    if have sshpass; then
        printf '%s\nexit\n' "$cmd" | \
            SSHPASS=x sshpass -e torsocks ssh -o StrictHostKeyChecking=accept-new \
                -o ConnectTimeout=60 -p "$PORT" "${USER_SSH}@${ONION}" 2>/dev/null
    else
        printf '%s\nexit\n' "$cmd" | \
            torsocks ssh -o StrictHostKeyChecking=accept-new \
                -o ConnectTimeout=60 -p "$PORT" "${USER_SSH}@${ONION}"
    fi
    echo "----------------------------------------"
}

ask() { local p="$1"; local v; read -r -p "$p" v; printf '%s' "$v"; }

if ! have torsocks; then echo "torsocks manquant (sudo pacman -S torsocks)"; exit 1; fi
if ! have sshpass; then
    echo "NB: sshpass absent → mot de passe demandé à chaque commande (n'importe lequel)."
    echo "    Pour l'automatiser :  sudo pacman -S sshpass"
    echo
fi

PS3=$'\nChoix ? '
options=(
    "info               - infos device"
    "wifi               - état WiFi / IP"
    "onion              - adresse .onion"
    "adc <n>            - lire une broche ADC"
    "gpio <n> <0|1>     - écrire une broche GPIO"
    "rfid info          - infos lecteur RFID"
    "rfid read          - lire un tag RFID (5s)"
    "ir rx              - capturer un signal IR (bouton pour stopper)"
    "rf rx              - écouter la radio CC1101"
    "rf scan            - scan de fréquences"
    "settings           - config Bruce"
    "gateway <ip> <port>- passer en passerelle vers un PC (reboot)"
    "gateway off        - repasser en shell local (reboot)"
    "jump -> PC ($PC_IP)- ssh -J rebond vers le PC (session interactive)"
    "commande libre     - taper une commande brute"
    "reboot             - redémarrer le T-Embed"
    "Quitter"
)

echo "=== Bruce-TorSSH : $USER_SSH@$ONION ==="
select opt in "${options[@]}"; do
    case "$REPLY" in
        1)  run_remote "info" ;;
        2)  run_remote "wifi" ;;
        3)  run_remote "onion" ;;
        4)  n=$(ask "Broche ADC: ");            run_remote "adc $n" ;;
        5)  n=$(ask "Broche GPIO: "); v=$(ask "Valeur 0/1: "); run_remote "gpio $n $v" ;;
        6)  run_remote "rfid info" ;;
        7)  run_remote "rfid read" ;;
        8)  run_remote "ir rx" ;;
        9)  run_remote "rf rx" ;;
        10) run_remote "rf scan" ;;
        11) run_remote "settings" ;;
        12) ip=$(ask "IP du PC: "); pt=$(ask "Port (22): "); pt=${pt:-22}; run_remote "gateway $ip $pt" ;;
        13) run_remote "gateway off" ;;
        14) echo ">>> jump host vers ${PC_IP} (session interactive)";
            torsocks ssh -o StrictHostKeyChecking=accept-new -J "${USER_SSH}@${ONION}" "bourbier@${PC_IP}";
            echo "----------------------------------------" ;;
        15) c=$(ask "Commande: ");              run_remote "$c" ;;
        16) run_remote "reboot" ;;
        17|q|Q) echo "Bye."; break ;;
        *)  echo "Choix invalide." ;;
    esac
done
