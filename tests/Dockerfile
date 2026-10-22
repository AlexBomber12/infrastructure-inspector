FROM infrastructure-inspector:ci
USER root
COPY tests/requirements.txt /opt/test-requirements.txt
RUN python -m pip install --no-cache-dir -r /opt/test-requirements.txt && python -m pip check
USER 65533:65533
