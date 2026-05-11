import os
import uuid
import subprocess
from fastapi import FastAPI, BackgroundTasks, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Sandbox API")

jobs = {}

class CodeSubmission(BaseModel):
  language: str
  code: str

def process_code(job_id: str, submission: CodeSubmission):
  jobs[job_id]["status"] = "RUNNING"

  # Create this submissions workspace under the cwd
  workspace = f"./workspace/{job_id}"
  os.makedirs(workspace, exist_ok = True)

  source_file = f"{workspace}/main.c"
  binary_file = f"{workspace}/binary"

  # Write the source code to source file
  with open(source_file, "w") as fp:
    fp.write(submission.code)

  # Compile the source file
  compile_cmd = ["gcc", "-static", source_file, "-o", binary_file]
  compile_process = subprocess.run(compile_cmd, capture_output = True, text = True)

  if compile_process.returncode != 0:
    # Update current job status
    jobs[job_id]["status"] = "COMPLETED"
    jobs[job_id]["output"] = "Compilation Error:\n" + compile_process.stderr
    return


  # Execute the compiled file
  hermes_path = "../hermes-core/hermes"

  execute_cmd = [hermes_path, binary_file]
  execute_process = subprocess.run(execute_cmd, capture_output = True, text = True)

  # Update job status
  jobs[job_id]["status"] = "COMPLETED"
  jobs[job_id]["output"] = execute_process.stdout + execute_process.stderr
  return

# -------------------------------- END POINTS -------------------------------------------

# Endpoint for submitting the code and get job ID. Asynchronous processing
@app.post("/submit")
async def submit_code(submission: CodeSubmission, background_tasks: BackgroundTasks):

  # Create a new unique job
  job_id = str(uuid.uuid4())
  jobs[job_id] = {"status" : "QUEUED", "output" : ""}

  # Delegate processing to a worker thread
  background_tasks.add_task(process_code, job_id, submission)

  return {"job_id" : job_id, "status" : "QUEUED"}

@app.get("/status/{job_id}")
async def get_status(job_id: str):

  if job_id not in jobs:
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job ID not found")
#    return {"error" : "Job ID not found"

  job_status = jobs[job_id]
  return job_status

if __name__ == "__main__":
  import uvicorn
  uvicorn.run("main:app", host = "0.0.0.0", port = 8000)

