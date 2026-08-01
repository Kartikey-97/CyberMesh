FROM python:3.12-slim
WORKDIR /app
COPY auth-service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY auth-service/ /app/auth_service/
COPY shared/ /app/shared/
EXPOSE 8081
CMD ["uvicorn", "auth_service.main:app", "--host", "0.0.0.0", "--port", "8081"]
