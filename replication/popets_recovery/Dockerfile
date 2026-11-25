FROM python:3.11.15-slim
WORKDIR /study
ENV PYTHONPATH=/study/src PYTHONDONTWRITEBYTECODE=1
COPY src/noticer_core/__init__.py src/noticer_core/recovery_schedule.py /study/src/noticer_core/
COPY tools/run_popets_recovery_matrix.py /study/run_popets_recovery_matrix.py
ENTRYPOINT ["python", "/study/run_popets_recovery_matrix.py"]
CMD ["/output"]
