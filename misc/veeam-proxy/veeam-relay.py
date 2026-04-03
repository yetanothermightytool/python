#!/usr/bin/env python3
import asyncio
import json
from typing import Optional, Literal
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

CONTAINER_IMAGE = "veeam-intelligence-mcp-server"
DOCKER_TIMEOUT  = 120

# Docker parameters
ACCEPT = "true"

class Ask(BaseModel):
  question: str = Field(..., min_length=1, max_length=10000)
  web_url: str = Field(..., description="Web URL")
  product_name: Literal["vbr", "vone"] = Field(..., description="Product name")

  @field_validator('question')
  @classmethod
  def validate_question(cls, v: str) -> str:
      if '\x00' in v:
          raise ValueError("Question contains invalid characters")
      return v.strip()

  @field_validator('web_url')
  @classmethod
  def validate_web_url(cls, v: str) -> str:
      if not v.startswith(("http://", "https://")):
          raise ValueError("web_url must start with http:// or https://")
      if '\x00' in v or '\n' in v:
          raise ValueError("web_url contains invalid characters")
      return v

def validate_mcp_response(stdout: str) -> dict:
  lines = stdout.strip().split('\n')
  responses = []

  for line in lines:
      if not line.strip():
          continue

      try:
          response = json.loads(line)

          if "jsonrpc" not in response or response["jsonrpc"] != "2.0":
              raise ValueError("Invalid JSON-RPC response")

          if "error" in response:
              error = response["error"]
              raise HTTPException(
                  status_code=500,
                  detail=f"MCP Error: {error.get('message', 'Unknown error')}"
              )

          responses.append(response)

      except json.JSONDecodeError as e:
          logger.error(f"JSON decode error: {e}, line: {line}")
          raise HTTPException(
              status_code=500,
              detail="Invalid JSON response from container"
          )

  if not responses:
      raise HTTPException(
          status_code=500,
          detail="No valid responses from container"
      )

  return responses

# Build the Docker command - check manually before the script executes
def build_docker_command(
  web_url: str,
  admin_username: Optional[str],
  admin_password: Optional[str],
  product_name: str
) -> list[str]:
   
  docker_cmd = [
      "/usr/bin/docker", "run",
      "-i",
      "--rm",
      #"--network", "none",
      "--memory", "512m",
      "--cpus", "1",
      "--pids-limit", "100",
      "--read-only",
      "--security-opt", "no-new-privileges",
  ]

  # Fix Parameters
  docker_cmd.extend(["-e", f"PRODUCT_NAME={product_name}"])
  docker_cmd.extend(["-e", f"ACCEPT_SELF_SIGNED_CERT={ACCEPT}"])

  # WEB_URL 
  docker_cmd.extend(["-e", f"WEB_URL={web_url}"])

  # Admin Credentials from Headers
  if not admin_username or not admin_password:
      raise HTTPException(
          status_code=401,
          detail="admin-username and admin-password headers required"
      )

  # Validate credentials
  if '\x00' in admin_username or '\n' in admin_username:
      raise HTTPException(status_code=400, detail="Invalid username")
  if '\x00' in admin_password or '\n' in admin_password:
      raise HTTPException(status_code=400, detail="Invalid password")

  docker_cmd.extend(["-e", f"ADMIN_USERNAME={admin_username}"])
  docker_cmd.extend(["-e", f"ADMIN_PASSWORD={admin_password}"])

  docker_cmd.append(CONTAINER_IMAGE)

  return docker_cmd

@app.post("/ask")
async def ask(
  req: Ask,
  admin_username: Optional[str] = Header(default=None),
  admin_password: Optional[str] = Header(default=None),
) -> JSONResponse:

  # MCP Requests 
  mcp_requests = [
      {
          "jsonrpc": "2.0",
          "id": 1,
          "method": "initialize",
          "params": {
              "protocolVersion": "2025-11-25",
              "capabilities": {},
              "clientInfo": {
                  "name": "http-proxy",
                  "version": "1.0"
              }
          }
      },
      {
          "jsonrpc": "2.0",
          "id": 2,
          "method": "tools/call",
          "params": {
              "name": "veeam-question-answering",
              "arguments": {
                  "question": req.question
              }
          }
      }
  ]

  stdin_payload = "\n".join(json.dumps(r) for r in mcp_requests) + "\n"

  # Build Docker command
  try:
      docker_cmd = build_docker_command(
          str(req.web_url),
          admin_username,
          admin_password,
          req.product_name
      )
  except HTTPException:
      raise
  except Exception as e:
      logger.error(f"Error building docker command: {e}")
      raise HTTPException(status_code=500, detail="Internal server error")

  # Execute container
  try:
      logger.info(f"Executing container for Veeam Intelligence query (URL: {req.web_url})")

      process = await asyncio.create_subprocess_exec(
          *docker_cmd,
          stdin=asyncio.subprocess.PIPE,
          stdout=asyncio.subprocess.PIPE,
          stderr=asyncio.subprocess.PIPE,
      )

      try:
          stdout_bytes, stderr_bytes = await asyncio.wait_for(
              process.communicate(input=stdin_payload.encode()),
              timeout=DOCKER_TIMEOUT
          )
      except asyncio.TimeoutError:
          process.kill()
          await process.communicate()
          logger.error("Container execution timeout")
          raise HTTPException(
              status_code=504,
              detail="Container execution timeout"
          )

      stdout = stdout_bytes.decode()
      stderr = stderr_bytes.decode()

      # Check return code
      if process.returncode != 0:
          logger.error(
              f"Container failed with code {process.returncode}: {stderr}"
          )
          raise HTTPException(
              status_code=500,
              detail=f"Container execution failed (code: {process.returncode})"
          )

      # Log Stderr
      if stderr:
          logger.warning(f"Container stderr: {stderr}")

      # Validate response
      responses = validate_mcp_response(stdout)

      # tools/call extract
      tool_response = next(
          (r for r in responses if r.get("id") == 2),
          None
      )

      if not tool_response:
          raise HTTPException(
              status_code=500,
              detail="No tool response found"
          )

      return JSONResponse(content={
          "success": True,
          "result": tool_response.get("result"),
      })

  except HTTPException:
      raise
  except Exception as e:
      logger.error(f"Unexpected error: {e}")
      raise HTTPException(
          status_code=500,
          detail="Internal server error"
      )

@app.get("/health")
def health():
  """Health-Check Endpoint"""
  return {"status": "healthy"}

if __name__ == "__main__":
  import uvicorn
  uvicorn.run(app, host="0.0.0.0", port=8443, ssl_certfile="certs/cert.pem", ssl_keyfile="certs/key.pem")

