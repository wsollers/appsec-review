from locust import HttpUser, task


class Web(HttpUser):
    @task
    def index(self):
        self.client.get("/")
