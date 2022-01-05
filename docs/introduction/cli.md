# Command Line Interface

The CLI tool primarily using pipenv to manage dependencies and pip virtual environments to not mismatch dependencies.

```bash
# Install dependencies and virtual environment
pipenv install
# [option] Install system wide
pipenv install --system
```

Once installed, you can just call the module using the following command(s):

```bash
# Using pipenv script
pipenv run main --help
# ... or
pipenv run python -m ghascompliance
```

