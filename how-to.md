dpkg-query -W -f='${Package} ${Version}\n' > packages.txt

python -u vuln-checker.py | tee vuln-output
