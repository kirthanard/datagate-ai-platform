import os
import json
import hashlib
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from werkzeug.exceptions import HTTPException
from google.cloud import storage
from google.cloud import bigquery
from google import genai
from google.genai import types

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

PROJECT_ID = os.environ.get("GCP_PROJECT", "datagate-ai-engine")
LOCATION = os.environ.get("GCP_REGION", "us-central1")

bq_client = bigquery.Client(project=PROJECT_ID)
storage_client = storage.Client(project=PROJECT_ID)

# Initialize strictly using Vertex AI ($300 GCP Free Tier Credits)
ai_client = genai.Client(
    vertexai=True,
    project=PROJECT_ID,
    location=LOCATION
)

def generate_payload_hash(payload_keys):
    sorted_keys = sorted(list(payload_keys))
    return hashlib.sha256(",".join(sorted_keys).encode('utf-8')).hexdigest()

@app.errorhandler(Exception)
def handle_global_exception(e):
    code = 500
    description = "Internal Application Server Exception"
    
    if isinstance(e, HTTPException):
        code = e.code
        description = e.description
    else:
        description = str(e)
        
    app.logger.error(f"CRITICAL EXCEPTION CAUGHT [HTTP {code}]: {description}", exc_info=True)
    
    return jsonify({
        "status": "ERROR",
        "http_code": code,
        "error": description,
        "timestamp": datetime.utcnow().isoformat()
    }), code

@app.route("/", methods=["GET"])
def render_control_center():
    return render_template("index.html")

@app.route("/admin", methods=["GET"])
def render_admin_dashboard():
    return render_template("admin.html")

def enforce_outbound_guardrails(row_data, mapping_dict):
    try:
        raw_product_id = row_data.get(mapping_dict.get("product_id"), "UNKNOWN_SKU")
        raw_quantity = row_data.get(mapping_dict.get("quantity"), 0)
        raw_revenue = row_data.get(mapping_dict.get("revenue"), 0.0)
        
        if not raw_product_id or str(raw_product_id).strip() == "":
            raw_product_id = "UNKNOWN_SKU"
            
        return {
            "product_id": raw_product_id,
            "quantity": raw_quantity,
            "revenue": raw_revenue
        }
    except Exception as e:
        logging.error(f"Guardrail Check Failure: Restoring defaults. Error: {str(e)}")
        return {"product_id": "CORRUPT_SKU_FALLBACK", "quantity": 0, "revenue": 0.0}

def normalize_and_type_cast(validated_row):
    try:
        raw_prod_id = validated_row["product_id"]
        raw_qty = validated_row["quantity"]
        raw_rev = validated_row["revenue"]

        clean_prod_id = str(raw_prod_id).strip()

        if str(raw_qty).isdigit():
            clean_qty = int(raw_qty)
        else:
            parsed_digits = ''.join(filter(str.isdigit, str(raw_qty)))
            clean_qty = int(parsed_digits) if parsed_digits else 0

        clean_rev_str = str(raw_rev).replace('$', '').replace(',', '').strip()
        clean_rev = float(clean_rev_str) if clean_rev_str else 0.0

        return {
            "product_id": clean_prod_id,
            "quantity": clean_qty,
            "revenue": clean_rev,
            "ingested_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise ValueError(f"Data Normalization Engine Aborted Row: {str(e)}")

@app.route("/api/queue", methods=["GET"])
def fetch_pending_queue():
    bucket_name = os.environ.get("QUARANTINE_BUCKET", "datagate-ai-engine-quarantine-vault")
    blobs = storage_client.list_blobs(bucket_name, prefix="failed_batches/")
    pending_list = []
    for blob in blobs:
        if blob.name.endswith('.json') and "pending_" in blob.name:
            content = blob.download_as_text()
            pending_list.append({
                "file_id": blob.name, 
                "data": json.loads(content)
            })
    return jsonify(pending_list), 200

@app.route("/validate", methods=["POST"])
def validate_ingestion_stream():
    request_json = request.get_json(silent=True)
    if not request_json or "payload" not in request_json:
        return jsonify({"status": "REJECTED", "error": "Missing payload structure."}), 400

    incoming_data = request_json["payload"]
    if not incoming_data or not isinstance(incoming_data, list) or len(incoming_data) == 0:
        return jsonify({"status": "REJECTED", "error": "Payload must be a non-empty list."}), 400

    # ---------------------------------------------------------
    # AGENT 1: Cyber Guard Agent (Threat Detection)
    # ---------------------------------------------------------
    sql_keywords = ["drop table", "union select", "alter table", "truncate table", "--", ";"]
    prompt_keywords = ["ignore previous instructions", "attack override", "system prompt", "you are now"]

    for row in incoming_data:
        if not isinstance(row, dict):
            continue
        for value in row.values():
            val_str = str(value).lower()
            is_sql = any(k in val_str for k in sql_keywords)
            is_prompt = any(k in val_str for k in prompt_keywords)

            if is_sql or is_prompt:
                threat_type = "SQL_INJECTION" if is_sql else "PROMPT_INJECTION"
                try:
                    threat_row = [{
                        "detected_at": datetime.utcnow().isoformat(),
                        "attacker_payload": str(value),
                        "threat_type": threat_type
                    }]
                    bq_client.insert_rows_json(bq_client.dataset("datagate_dw").table("security_threat_logs"), threat_row)
                except Exception as bq_err:
                    app.logger.error(f"Failed logging threat: {str(bq_err)}")

                return jsonify({
                    "status": "REJECTED_SECURITY_THREAT",
                    "error": "Security threat detected.",
                    "threat_type": threat_type,
                    "rationale": f"Malicious string signature detected: '{val_str}'"
                }), 403

    try:
        sample_row_keys = list(incoming_data[0].keys())
    except (IndexError, AttributeError, TypeError):
        sample_row_keys = []

    if not sample_row_keys:
        return jsonify({"status": "REJECTED", "error": "Empty record keys."}), 400

    current_hash = generate_payload_hash(sample_row_keys)

    # ---------------------------------------------------------
    # AGENT 2: Schema Drifter Agent (Cache Lookup & Rule Engine)
    # ---------------------------------------------------------
    query = f"SELECT mapped_columns, status FROM `datagate_dw.learned_rules` WHERE template_hash = '{current_hash}' LIMIT 1"
    try:
        query_job = bq_client.query(query)
        results = list(query_job.result())

        if results:
            rule = results[0]
            if rule.status == "APPROVED":
                saved_mapping = json.loads(rule.mapped_columns)
                mapped_rows = []
                for row in incoming_data:
                    try:
                        safe_row = enforce_outbound_guardrails(row, saved_mapping)
                        normalized_row = normalize_and_type_cast(safe_row)
                        mapped_rows.append(normalized_row)
                    except Exception as err:
                        logging.error(f"Skipping row: {str(err)}")
                        continue
                table_ref = bq_client.dataset("datagate_dw").table("transactions")
                bq_client.insert_rows_json(table_ref, mapped_rows)
                return jsonify({"status": "AUTO_SUCCESS", "message": "Known schema signature matched."}), 200
            elif rule.status == "BANNED":
                return jsonify({"status": "REJECTED", "error": "This template layout is banned."}), 403
    except Exception as bq_lookup_err:
        app.logger.error(f"BigQuery lookup error: {str(bq_lookup_err)}")

    # ---------------------------------------------------------
    # AGENT 3: Consensus Engine Agent (Vertex AI LLM Schema Mapping)
    # ---------------------------------------------------------
    quarantine_bucket_name = os.environ.get("QUARANTINE_BUCKET", "datagate-ai-engine-quarantine-vault")
    storage_bucket = storage_client.bucket(quarantine_bucket_name)
    blob = storage_bucket.blob(f"failed_batches/pending_{current_hash}.json")

    if blob.exists():
        existing_package = json.loads(blob.download_as_text())
        return jsonify({
            "status": "QUARANTINED",
            "message": "Layout format actively collecting votes.",
            "template_hash": current_hash,
            "total_votes_logged": existing_package.get("total_votes", 0)
        }), 200

    blueprint_metadata = {
        "extracted_headers": sample_row_keys,
        "sample_rows": incoming_data[:5]
    }

    prompt = f"""
    You are an enterprise Data Quality Engine.
    Analyze this raw incoming data sample block: {json.dumps(blueprint_metadata)}.

    TARGET METRICS TO MAP:
    - product_id (string product/SKU code)
    - quantity (integer count of items)
    - revenue (numeric price/monetary total)

    INSTRUCTIONS:
    1. Inspect sample_rows values. If they contain corrupted text or garbage strings, set is_valid_data to false.
    2. If values are clean, set is_valid_data to true and map extracted_headers to product_id, quantity, and revenue.

    Return EXACT JSON format:
    {{
        "is_valid_data": true,
        "mapping_dictionary": {{
            "product_id": "<column_name>",
            "quantity": "<column_name>",
            "revenue": "<column_name>"
        }}
    }}
    """

    evaluation = None
    llm_error_msg = ""

    # Call Vertex AI directly using verified working model
    try:
        response = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json"
            )
        )
        evaluation = json.loads(response.text)
    except Exception as e:
        llm_error_msg = str(e)
        app.logger.error(f"[ConsensusEngine] LLM Error: {llm_error_msg}")

    if evaluation is None:
        return jsonify({"status": "REJECTED", "error": f"LLM Processing Exception: {llm_error_msg}"}), 500

    if evaluation.get("is_valid_data", False):
        quarantine_package = {
            "template_hash": current_hash,
            "original_columns": sample_row_keys,
            "suggested_mapping": evaluation.get("mapping_dictionary", {}),
            "total_votes": 0,
            "approval_votes": 0,
            "voted_operators": [],
            "raw_received_data": request_json
        }
        blob.upload_from_string(json.dumps(quarantine_package), content_type="application/json")
        return jsonify({
            "status": "QUARANTINED",
            "message": "New structural pattern isolated for UI validation voting.",
            "template_hash": current_hash,
            "suggested_mapping": evaluation.get("mapping_dictionary", {})
        }), 200
    else:
        return jsonify({
            "status": "REJECTED",
            "error": "Structural anomalies caught during audit loop."
        }), 400

@app.route("/vote", methods=["POST"])
def handle_human_vote():
    try:
        request_json = request.get_json(silent=True) or {}
        template_hash = request_json.get("template_hash")
        vote_action = request_json.get("vote", "APPROVE").upper()
        operator_id = request_json.get("operator_id", "anonymous_engineer")

        bucket_name = os.environ.get("QUARANTINE_BUCKET", "datagate-ai-engine-quarantine-vault")
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(f"failed_batches/pending_{template_hash}.json")

        if not blob.exists():
            return jsonify({
                "status": "SUCCESS",
                "total_votes_logged": 5,
                "approval_votes_logged": 5,
                "rule_status": "ALREADY_COMPLETED",
                "voted_operators": [operator_id]
            }), 200

        package = json.loads(blob.download_as_text())
        if "voted_operators" not in package:
            package["voted_operators"] = []

        if operator_id in package["voted_operators"]:
            return jsonify({
                "status": "VOTE_REJECTED",
                "error": "Operator has already voted on this instance."
            }), 403

        package["voted_operators"].append(operator_id)
        total_votes = package.get("total_votes", 0) + 1
        approval_votes = package.get("approval_votes", 0) + (1 if vote_action == "APPROVE" else 0)

        package["total_votes"] = total_votes
        package["approval_votes"] = approval_votes
        
        status = "COLLECTING_VOTES"
        
        if total_votes >= 5:
            acceptance_score = (approval_votes / total_votes) * 100
            status = "APPROVED" if acceptance_score > 50 else "BANNED"
            
            original_cols_list = package.get("original_columns", [])
            original_cols_str = ", ".join(original_cols_list) if isinstance(original_cols_list, list) else str(original_cols_list)
            
            suggested_map_dict = package.get("suggested_mapping", {})
            suggested_map_str = json.dumps(suggested_map_dict) if isinstance(suggested_map_dict, dict) else str(suggested_map_dict)
            
            rule_row = [{
                "template_hash": str(template_hash),
                "original_columns": original_cols_str,
                "mapped_columns": suggested_map_str,
                "approval_count": int(total_votes),
                "status": str(status),
                "approval_votes": int(approval_votes)
            }]
            
            table_ref = bq_client.dataset("datagate_dw").table("learned_rules")
            errors = bq_client.insert_rows_json(table_ref, rule_row)
            
            if errors:
                raise Exception(f"BigQuery Write Errors: {errors}")
                
            blob.delete() 
        else:
            blob.upload_from_string(json.dumps(package), content_type="application/json")

        return jsonify({
            "status": "SUCCESS", 
            "total_votes_logged": total_votes, 
            "approval_votes_logged": approval_votes,
            "rule_status": status,
            "voted_operators": package["voted_operators"]
        }), 200

    except Exception as e:
        return jsonify({"status": "ERROR", "error": str(e)}), 500

@app.route("/api/admin/metrics", methods=["GET"])
def fetch_admin_metrics():
    try:
        query = """
            SELECT 
                template_hash, 
                original_columns, 
                approval_count, 
                status,
                approval_votes,
                CASE 
                    WHEN approval_count > 0 THEN SAFE_CAST(ROUND((approval_votes / approval_count) * 100, 0) AS STRING)
                    ELSE '0'
                END as calculated_percentage
            FROM `datagate_dw.learned_rules` 
            LIMIT 50
        """
        query_job = bq_client.query(query)
        results = list(query_job.result())
        
        rules_list = []
        approved_count = 0
        banned_count = 0
        
        for row in results:
            stat = row.get("status", "PENDING")
            if stat == "APPROVED": approved_count += 1
            elif stat == "BANNED": banned_count += 1
                
            rules_list.append({
                "template_hash": row.get("template_hash"), 
                "original_columns": row.get("original_columns"), 
                "status": stat, 
                "approval_percentage": row.get("calculated_percentage") + "%", 
                "total_reviews": row.get("approval_count")
            })

        return jsonify({
            "status": "SUCCESS", 
            "metrics": {
                "active_auto_pass_rules": approved_count, 
                "banned_signatures": banned_count, 
                "total_cataloged_variants": len(rules_list)
            }, 
            "rules_registry": rules_list
        }), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "error": str(e)}), 500

@app.route("/api/admin/threats", methods=["GET"])
def fetch_security_threats():
    try:
        days = request.args.get("days", "7")
        try:
            days_int = int(days)
        except ValueError:
            days_int = 7

        query = f"""
            SELECT 
                FORMAT_TIMESTAMP('%Y-%m-%d %H:%M:%S', detected_at) as detected_at, 
                attacker_payload, 
                threat_type 
            FROM `datagate_dw.security_threat_logs` 
            WHERE detected_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days_int} DAY) 
            ORDER BY detected_at DESC 
            LIMIT 50
        """
        query_job = bq_client.query(query)
        threats = [{"detected_at": row.detected_at, "attacker_payload": row.attacker_payload, "threat_type": row.threat_type} for row in query_job.result()]
            
        return jsonify({"status": "SUCCESS", "filter_window_days": days_int, "threats": threats}), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
    
    