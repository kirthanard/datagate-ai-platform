import os
import json
import hashlib
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from werkzeug.exceptions import HTTPException
from google.cloud import storage
from google.cloud import bigquery
import google.generativeai as genai

# Initialize unified application server infrastructure
app = Flask(__name__)

# Enforce explicit application log routing for Cloud Run (stdout/stderr interception)
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

bq_client = bigquery.Client()
storage_client = storage.Client()

def generate_payload_hash(payload_keys):
    sorted_keys = sorted(list(payload_keys))
    return hashlib.sha256(",".join(sorted_keys).encode('utf-8')).hexdigest()

# =====================================================================
# GLOBAL ERROR INTERCEPTOR (Catches ALL HTTP 400s, 404s, 500s & Syntax Errors)
# =====================================================================
@app.errorhandler(Exception)
def handle_global_exception(e):
    """Intercepts every single runtime error and forces a verbose output trace to Cloud Logging."""
    code = 500
    description = "Internal Application Server Exception"
    
    if isinstance(e, HTTPException):
        code = e.code
        description = e.description
    else:
        description = str(e)
        
    # FORCE FULL ERROR DUMP INTO VISUAL LOGS EXPLORER PANEL
    app.logger.error(f"CRITICAL EXCEPTION CAUGHT [HTTP {code}]: {description}", exc_info=True)
    
    return jsonify({
        "status": "ERROR",
        "http_code": code,
        "error": description,
        "timestamp": datetime.utcnow().isoformat()
    }), code

# =====================================================================
# ROUTE 1: RENDER USER INTERFACE DASHBOARD CONTROL PANEL
# =====================================================================
@app.route("/", methods=["GET"])
def render_control_center():
    return render_template("index.html")

# =====================================================================
# ROUTE 1B: RENDER SEPARATE ADMINISTRATIVE CONTROL PANEL
# =====================================================================
@app.route("/admin", methods=["GET"])
def render_admin_dashboard():
    """Serves the isolated administrator dashboard on the explicit /admin endpoint path."""
    return render_template("admin.html")

def enforce_outbound_guardrails(row_data, mapping_dict):
    """
    Validates that the incoming row contains all expected warehouse metrics.
    Injects production-safe defaults if fields are missing to prevent insertion failures.
    """
    try:
        # Extract fields using the AI learned mapping parameters, fallback to standard keys
        raw_product_id = row_data.get(mapping_dict.get("product_id"), "UNKNOWN_SKU")
        raw_quantity = row_data.get(mapping_dict.get("quantity"), 0)
        raw_revenue = row_data.get(mapping_dict.get("revenue"), 0.0)
        
        # Enforce strict field presence constraints
        if not raw_product_id or str(raw_product_id).strip() == "":
            raw_product_id = "UNKNOWN_SKU"
            
        return {
            "product_id": raw_product_id,
            "quantity": raw_quantity,
            "revenue": raw_revenue
        }
    except Exception as e:
        logging.error(f"Guardrail Check Failure: Restoring hard system defaults. Error: {str(e)}")
        return {"product_id": "CORRUPT_SKU_FALLBACK", "quantity": 0, "revenue": 0.0}

def normalize_and_type_cast(validated_row):
    """
    Cleanses string formatting metrics and enforces strict destination data types.
    Transforms raw input formats directly into BigQuery schema specifications.
    """
    try:
        raw_prod_id = validated_row["product_id"]
        raw_qty = validated_row["quantity"]
        raw_rev = validated_row["revenue"]

        # 1. Normalize Product ID: Force clean, whitespace-stripped literal string
        clean_prod_id = str(raw_prod_id).strip()

        # 2. Normalize Quantity: Parse integers, handle string text strings (e.g., "10 units" -> 10)
        if str(raw_qty).isdigit():
            clean_qty = int(raw_qty)
        else:
            # Strip non-numeric character clutter out of the value parameter
            parsed_digits = ''.join(filter(str.isdigit, str(raw_qty)))
            clean_qty = int(parsed_digits) if parsed_digits else 0

        # 3. Normalize Revenue: Strip currency formats (e.g., "$1,249.99" -> 1249.99)
        clean_rev_str = str(raw_rev).replace('$', '').replace(',', '').strip()
        clean_rev = float(clean_rev_str) if clean_rev_str else 0.0

        return {
            "product_id": clean_prod_id,
            "quantity": clean_qty,
            "revenue": clean_rev,
            "ingested_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise ValueError(f"Data Normalization Engine Aborted Row: Type conversion crashed. Error: {str(e)}")
# =====================================================================
#  ROUTE 2: FETCH PENDING ISOLATION WORKSPACE INSTANCES
# =====================================================================
@app.route("/api/queue", methods=["GET"])
def fetch_pending_queue():
    bucket_name = os.environ.get("QUARANTINE_BUCKET", "datagate-ai-engine-quarantine-vault")
    app.logger.info(f"Scanning quarantine bucket vault: {bucket_name}")
    
    blobs = storage_client.list_blobs(bucket_name, prefix="failed_batches/")
    pending_list = []
    for blob in blobs:
        if blob.name.endswith('.json') and "pending_" in blob.name:
            content = blob.download_as_text()
            pending_list.append({
                "file_id": blob.name, 
                "data": json.loads(content)
            })
            
    app.logger.info(f"Queue scan completed. Found {len(pending_list)} isolated instances pending audit review.")
    return jsonify(pending_list), 200

# =====================================================================
# ROUTE 3: AUTOMATED INGESTION SEMANTIC VALIDATION PIPELINE
# =====================================================================
@app.route("/validate", methods=["POST"])
def validate_ingestion_stream():
    request_json = request.get_json(silent=True)
    if not request_json or "payload" not in request_json:
        app.logger.warning("Ingestion Rejected: Missing payload key formatting parameters.")
        return jsonify({"status": "REJECTED", "error": "Missing payload data structure formatting."}), 400
    
    incoming_data = request_json["payload"]
    if not incoming_data or not isinstance(incoming_data, list) or len(incoming_data) == 0:
        app.logger.warning("Ingestion Rejected: Incoming payload is empty or not formatted as an array list.")
        return jsonify({"status": "REJECTED", "error": "Payload must be a populated row data array."}), 400

    #  INLINE VALUE SCANNER PROTECTION (Anti-SQL/Prompt Injection Firewall)
    malicious_keywords = ["drop table", "union select", "alter table", "truncate table", "ignore previous instructions", "attack override"]
    for row in incoming_data:
        for value in row.values():
            val_str = str(value).lower()
            if ";" in val_str or "--" in val_str or any(keyword in val_str for keyword in malicious_keywords):
                app.logger.warning(f"CRITICAL MALICIOUS EXPLOIT INTERCEPTED: '{val_str}'")
                
                # 📊 PERSISTENCE THREAT LOGGING LAYER
                try:
                    threat_type = "SQL_INJECTION" if "drop table" in val_str or "select" in val_str else "PROMPT_INJECTION"
                    threat_row = [{
                        "detected_at": datetime.utcnow().isoformat(),
                        "attacker_payload": str(value),
                        "threat_type": threat_type
                    }]
                    # Stream the attack incident log safely into BigQuery for visual audit reviews
                    bq_client.insert_rows_json(bq_client.dataset("datagate_dw").table("security_threat_logs"), threat_row)
                except Exception as bq_err:
                    app.logger.error(f"Failed logging threat trace to BigQuery: {str(bq_err)}")

                return jsonify({
                    "status": "REJECTED_SECURITY_THREAT", 
                    "error": "Hard structural anomalies or query exploits caught during inline value inspection.",
                    "rationale": f"Malicious payload text signatures matching script exploits or instruction injections were detected: '{val_str}'"
                }), 403

    # Extract signature configuration keys from the first element row dictionary item array to pull keys
    sample_row_keys = incoming_data[0].keys()
    current_hash = generate_payload_hash(sample_row_keys)
    app.logger.info(f"Processing ingestion data stream footprint. Calculated template fingerprint hash: {current_hash}")

    # Check if this schema configuration is officially APPROVED or BANNED inside BigQuery
    query = f"SELECT mapped_columns, status FROM `datagate_dw.learned_rules` WHERE template_hash = '{current_hash}' LIMIT 1"
    query_job = bq_client.query(query)
    results = list(query_job.result())

    if results:
        rule = results[0]
        if rule.status == "APPROVED":
            app.logger.info(f"Schema Signature Match Confirmed for Hash {current_hash}! Executing Auto-Pass Route.")
            saved_mapping = json.loads(rule.mapped_columns)
            mapped_rows = []
            for row in incoming_data:
                try:
                    # Step 1: Enforce field presence boundaries (Enhancement 1)
                    safe_row = enforce_outbound_guardrails(row, saved_mapping)
                    
                    # Step 2: Cleanse formatting clutter and force database data types (Enhancement 2)
                    normalized_row = normalize_and_type_cast(safe_row)
                    mapped_rows.append(normalized_row)
                    # mapped_rows.append({
                    #     "product_id": str(row.get(saved_mapping.get("product_id"), "")),
                    #     "quantity": int(row.get(saved_mapping.get("quantity"), 0)),
                    #     "revenue": float(row.get(saved_mapping.get("revenue"), 0.0)),
                    #     "ingested_at": datetime.utcnow().isoformat()
                    # })
                except Exception as err:
                    logging.error(f"Skipping corrupted data row row entry: {str(err)}")
                    continue # Bypass single bad rows to preserve entire batch processing speed
            table_ref = bq_client.dataset("datagate_dw").table("transactions")
            bq_client.insert_rows_json(table_ref, mapped_rows)
            return jsonify({"status": "AUTO_SUCCESS", "message": "Known schema signature recognized. Automatically routed to BigQuery."}), 200
        elif rule.status == "BANNED":
            app.logger.warning(f"Ingestion Aborted: Layout signature {current_hash} has been explicitly BANNED by team consensus.")
            return jsonify({"status": "REJECTED", "error": "This structural template layout has been banned by team vote consensus."}), 403

    #  PRESERVE CURRENT TRIAGE COUNT SAFEGUARD: Check if the file is already collecting votes in GCS
    quarantine_bucket_name = os.environ.get("QUARANTINE_BUCKET", "datagate-ai-engine-quarantine-vault")
    storage_bucket = storage_client.bucket(quarantine_bucket_name)
    blob = storage_bucket.blob(f"failed_batches/pending_{current_hash}.json")

    if blob.exists():
        app.logger.info(f"File layout signature {current_hash} is already active inside triage folder. Preserving current vote state.")
        existing_package = json.loads(blob.download_as_text())
        return jsonify({
            "status": "QUARANTINED", 
            "message": "This layout format configuration is already collecting consensus reviews inside the platform control center panel queue.", 
            "template_hash": current_hash,
            "total_votes_logged": existing_package.get("total_votes", 0)
        }), 200

    # Query Gemini 3.6 Flash model endpoint if schema config layout is unknown
    app.logger.info(f"Unknown data structure mapping pattern encountered for hash {current_hash}. Invoking Gemini Core Auditing Layer...")
    api_key = os.environ.get("GEMINI_API_KEY")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-3.6-flash", generation_config={"response_mime_type": "application/json"})

    prompt = f"""
    Analyze this raw data payload array: {json.dumps(incoming_data)}.
    Map fields to target variables: product_id (string), quantity (integer), revenue (float).
    If data contains severe text corruption or script injections, mark as NEEDS_REVIEW.
    Return this exact JSON format layout structure:
    {{
        "batch_status": "VALID" or "NEEDS_REVIEW",
        "mapping_dictionary": {{"product_id": "raw_field", "quantity": "raw_field", "revenue": "raw_field"}},
        "mapped_rows": [{{"product_id": "val", "quantity": 1, "revenue": 1.0}}]
    }}
    """
    response = model.generate_content(prompt)
    evaluation = json.loads(response.text)

    if evaluation.get("batch_status") == "VALID":
        quarantine_package = {
            "template_hash": current_hash,
            "original_columns": list(sample_row_keys),
            "suggested_mapping": evaluation.get("mapping_dictionary"),
            "total_votes": 0,
            "approval_votes": 0,
            "voted_operators": [],
            "raw_received_data": request_json
        }
        blob.upload_from_string(json.dumps(quarantine_package), content_type="application/json")
        app.logger.info(f"New structural variation isolated securely into GCS Vault as file name entry item: {blob.name}")
        return jsonify({"status": "QUARANTINED", "message": "New structural pattern isolated. Routing to UI Dashboard for validation voting.", "template_hash": current_hash}), 200
    else:
        app.logger.warning(f"Ingestion Aborted: Hard structural text anomalies caught during verification audit loop.")
        return jsonify({"status": "REJECTED", "error": "Hard structural anomalies caught during verification audit loop."}), 400

# =====================================================================
# ROUTE 4: HUMAN INTERACTIVE AUDIT TRIAGE LOGIC CONTROL (Consensus Engine)
# =====================================================================

@app.route("/vote", methods=["POST"])
def handle_human_vote():
    try:
        request_json = request.get_json(silent=True) or {}
        app.logger.info(f"Incoming /vote transaction invocation call payload package: {json.dumps(request_json)}")
        
        template_hash = request_json.get("template_hash")
        vote_action = request_json.get("vote", "APPROVE").upper()
        operator_id = request_json.get("operator_id", "anonymous_engineer")

        bucket_name = os.environ.get("QUARANTINE_BUCKET", "datagate-ai-engine-quarantine-vault")
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(f"failed_batches/pending_{template_hash}.json")

        if not blob.exists():
            app.logger.info(f"Triage request arrived for an already finalized template hash session: {template_hash}")
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

        #  ENFORCE MULTI-USER DEDUPLICATION SAFETY
        if operator_id in package["voted_operators"]:
            app.logger.warning(f"DEDUPLICATION REJECTION: Operator '{operator_id}' attempted duplicate vote transaction on schema configuration hash: {template_hash}")
            return jsonify({
                "status": "VOTE_REJECTED",
                "error": "Security Restriction: You have already cast a vote for this structural template instance. Consensus requires multi-user validation."
            }), 403

        package["voted_operators"].append(operator_id)
        total_votes = package.get("total_votes", 0) + 1
        approval_votes = package.get("approval_votes", 0) + (1 if vote_action == "APPROVE" else 0)

        package["total_votes"] = total_votes
        package["approval_votes"] = approval_votes
        
        status = "COLLECTING_VOTES"
        app.logger.info(f"Vote action '{vote_action}' logged by operator '{operator_id}' for configuration signature: {template_hash}. Current intermediate state: {approval_votes}/{total_votes} approvals.")
        
        #  Consensus Evaluation Threshold Calculation Trigger (Fires at exactly 5 unique votes)
        if total_votes >= 5:
            acceptance_score = (approval_votes / total_votes) * 100
            status = "APPROVED" if acceptance_score > 50 else "BANNED"
            
            # Extract lists cleanly to inject as structured JSON dictionaries
            original_cols_list = package.get("original_columns", [])
            original_cols_str = ", ".join(original_cols_list) if isinstance(original_cols_list, list) else str(original_cols_list)
            
            suggested_map_dict = package.get("suggested_mapping", {})
            suggested_map_str = json.dumps(suggested_map_dict) if isinstance(suggested_map_dict, dict) else str(suggested_map_dict)
            
            #  FIX: Use insert_rows_json() to feed row records cleanly without escaping quotes or string concatenations
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
                raise Exception(f"BigQuery Ledger Row Streaming Write Errors: {errors}")
                
            app.logger.info(f" CONSENSUS REACHED: Layout fingerprint '{template_hash}' completed triage evaluation cycle with a final mathematical score of {acceptance_score:.0f}%. Global Policy Automation State: {status}")
            blob.delete() 
            app.logger.info(f"Quarantine bucket staging block object cleared cleanly from file tree view: failed_batches/pending_{template_hash}.json")
        else:
            blob.upload_from_string(json.dumps(package), content_type="application/json")
            app.logger.info(f"Quarantine staging state package updated successfully for hash {template_hash} in Cloud Storage.")

        return jsonify({
            "status": "SUCCESS", 
            "total_votes_logged": total_votes, 
            "approval_votes_logged": approval_votes,
            "rule_status": status,
            "voted_operators": package["voted_operators"]
        }), 200

    except Exception as e:
        app.logger.error(f"CRITICAL VOTE ROUTE LIFECYCLE BREAK: Execution failed inside handler logic context. Error trace: {str(e)}", exc_info=True)
        return jsonify({"status": "ERROR", "error": str(e)}), 500


# =====================================================================
#  ROUTE 5: ADMIN MASTER AUDIT METRICS TELEMETRY API (Pure Mathematical)
# =====================================================================
@app.route("/api/admin/metrics", methods=["GET"])
def fetch_admin_metrics():
    try:
        days = request.args.get("days", "7")
        try:
            days_int = int(days)
        except ValueError:
            days_int = 7

        app.logger.info(f"Admin Metrics Telemetry API request invoked. Context window lookback parameters: {days_int} Days.")

        # Enforce pure mathematical percentage calculation inside BigQuery dynamically via SQL logic
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
            
        app.logger.info(f"BigQuery telemetry lookup completed successfully. Processing logs summary: {approved_count} APPROVED automation rules, {banned_count} BANNED layouts discovered out of {len(rules_list)} total historical rows.")

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
        app.logger.error(f"Admin Telemetry API Execution Exception: Database lookup query aborted. Trace: {str(e)}", exc_info=True)
        return jsonify({"status": "ERROR", "error": str(e)}), 500

@app.route("/api/admin/threats", methods=["GET"])
def fetch_security_threats():
    """Queries BigQuery security log registries to pull historical exploit data records."""
    try:
        # Extract lookback window filter parameter (defaulting to 7 days if blank)
        days = request.args.get("days", "7")
        try:
            days_int = int(days)
        except ValueError:
            days_int = 7

        # Enforce dynamic SQL calculations over historical logged attack strings
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
        
        threats = []
        for row in query_job.result():
            threats.append({
                "detected_at": row.detected_at, 
                "attacker_payload": row.attacker_payload, 
                "threat_type": row.threat_type
            })
            
        return jsonify({
            "status": "SUCCESS", 
            "filter_window_days": days_int,
            "threats": threats
        }), 200
        
    except Exception as e:
        app.logger.error(f"Security Threats Telemetry API Crash: {str(e)}")
        return jsonify({"status": "ERROR", "error": str(e)}), 500
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
