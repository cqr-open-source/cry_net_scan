## Set pre-commit, when libraries are installed:

```bash
pre-commit install
pre-commit run --all-files
```

## Create a binary file for full application using pyinstaller:

```bash
pyinstaller --onefile --add-binary 'tools/linux/nuclei/nuclei:tools/linux/nuclei' --add-binary 'tools/linux/afrog/afrog:tools/linux/afrog' --add-binary 'tools/linux/rustscan/rustscan:tools/linux/rustscan' --add-binary 'tools/linux/webanalyze/webanalyze:tools/linux/webanalyze' main.py
```