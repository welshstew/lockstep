# Browser tests and screenshot generation. Playwright's image ships the browsers
# (/ms-playwright) and their system libraries; the Python packages are pinned here.
FROM mcr.microsoft.com/playwright/python:v1.64.1-noble@sha256:330d401ae23c905896a0c26c66c36fc971b621519e7b11b435a8328d7bf6e031
RUN pip install --no-cache-dir --break-system-packages playwright==1.64.1 pytest==9.2.0 httpx==0.28.1 \
 && mkdir -p /reports && chown pwuser /reports
# Baked in (not bind-mounted) so the suite also runs in CI, where the Docker host can't see
# the job's checkout. Results go to /reports; copy them out with `docker cp`.
COPY --chown=pwuser . /e2e
WORKDIR /e2e
# The image's non-root user; browsers in /ms-playwright are readable by it.
USER pwuser
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml=/reports/junit.xml", "tests"]
