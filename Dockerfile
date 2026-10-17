FROM apify/actor-python-playwright:3.12

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir playwright \
    && playwright install chromium

COPY . ./
CMD ["python3", "-m", "src"]
