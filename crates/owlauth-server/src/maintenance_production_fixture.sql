INSERT INTO projects (id,public_id,display_name,status,metadata_revision,security_revision)
VALUES ('10000000-0000-0000-0000-000000000001','prj_retention','Retention Project','active',1,1);
INSERT INTO project_policies (project_id) VALUES ('10000000-0000-0000-0000-000000000001');
INSERT INTO applications (id,project_id,public_id,display_name,application_type,status,revision,metadata_revision,security_revision)
VALUES ('10000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000001','app_retention','Retention App','web','active',1,1,1);
WITH material AS (
 INSERT INTO protected_materials
 (id,scope_kind,project_id,owner_kind,owner_id,generation,material_kind,provider_id,provider_format_version,context_version,context_digest,opaque_value,safe_fingerprint,state)
 VALUES ('10000000-0000-0000-0000-000000000003','project','10000000-0000-0000-0000-000000000001','provider_secret','10000000-0000-0000-0000-000000000004',1,'configuration_secret','software',1,1,decode(repeat('03',32),'hex'),decode('01','hex'),decode(repeat('02',32),'hex'),'live') RETURNING id)
INSERT INTO provider_configurations
(id,project_id,provider_key,kind,display_name,issuer,client_id,callback_url,secret_material_id,status,revision)
SELECT '10000000-0000-0000-0000-000000000004','10000000-0000-0000-0000-000000000001','oidc-retention','oidc','OIDC Retention','https://issuer.example.test','client','https://runtime.example.test/callback',id,'active',1 FROM material;
BEGIN;
INSERT INTO project_users (id,project_id,public_id,status,user_revision,security_revision,base_profile_digest,display_name)
VALUES ('10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000001','usr_retention','active',1,1,decode(repeat('04',32),'hex'),'Ada');
INSERT INTO linked_identities (id,project_id,user_id,created_via_provider_configuration_id,issuer,subject,status,identity_revision,source_profile_digest,display_name,observed_at)
VALUES ('10000000-0000-0000-0000-000000000006','10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000004','https://issuer.example.test','retention-subject','active',1,public.owlauth_provider_source_profile_digest('Ada',NULL,NULL),'Ada',transaction_timestamp());
UPDATE project_users SET primary_profile_identity_id='10000000-0000-0000-0000-000000000006' WHERE id='10000000-0000-0000-0000-000000000005';
COMMIT;
INSERT INTO application_user_bindings (id,project_id,application_id,user_id,status,binding_revision)
VALUES ('10000000-0000-0000-0000-000000000007','10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000005','active',1);

INSERT INTO application_sessions
(id,project_id,application_id,user_id,binding_id,status,session_revision,project_security_revision,application_security_revision,user_security_revision,claims_revision,policy_session_revision,authenticated_at,absolute_expires_at,created_at,updated_at)
VALUES ('10000000-0000-0000-0000-000000000012','10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000007','expired',1,1,1,1,1,1,transaction_timestamp()-interval '32 days',transaction_timestamp()-interval '2 days',transaction_timestamp()-interval '32 days',transaction_timestamp()-interval '2 days');
INSERT INTO refresh_families
(id,project_id,application_id,user_id,application_session_id,status,family_revision,current_generation,allowed_clock_skew_seconds,absolute_expires_at,created_at,updated_at)
VALUES ('10000000-0000-0000-0000-000000000013','10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000005','10000000-0000-0000-0000-000000000012','expired',1,1,60,transaction_timestamp()-interval '2 days',transaction_timestamp()-interval '32 days',transaction_timestamp()-interval '2 days');
INSERT INTO refresh_token_generations
(id,project_id,family_id,application_id,user_id,generation,token_digest,token_digest_key_version,status,consumed_at,retain_until,created_at)
VALUES ('10000000-0000-0000-0000-000000000014','10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000013','10000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000005',1,decode(repeat('05',32),'hex'),1,'consumed',transaction_timestamp()-interval '31 days',transaction_timestamp()-interval '1 day',transaction_timestamp()-interval '32 days');

BEGIN;
INSERT INTO protected_materials
(id,scope_kind,project_id,owner_kind,owner_id,generation,material_kind,provider_id,provider_format_version,context_version,context_digest,state)
VALUES ('10000000-0000-0000-0000-000000000015','project','10000000-0000-0000-0000-000000000001','project_smtp','10000000-0000-0000-0000-000000000016',1,'configuration_secret','software',1,1,decode(repeat('06',32),'hex'),'pending');
INSERT INTO project_smtp_configurations
(id,project_id,status,generation,revision,security_eligibility_revision,host,port,tls_mode,sender_address,sender_name,reply_to,safe_fingerprint,credential_material_id,created_at,updated_at)
VALUES ('10000000-0000-0000-0000-000000000016','10000000-0000-0000-0000-000000000001','active',1,1,1,'smtp.example.com',465,'implicit_tls','login@example.com','OwlAuth','reply@example.com',decode(repeat('07',32),'hex'),'10000000-0000-0000-0000-000000000015',transaction_timestamp()-interval '40 days',transaction_timestamp()-interval '40 days');
UPDATE protected_materials SET state='live',opaque_value=decode(repeat('08',64),'hex'),safe_fingerprint=decode(repeat('07',32),'hex'),updated_at=transaction_timestamp()-interval '40 days' WHERE id='10000000-0000-0000-0000-000000000015';
COMMIT;
BEGIN;
INSERT INTO protected_materials
(id,scope_kind,project_id,owner_kind,owner_id,generation,material_kind,provider_id,provider_format_version,context_version,context_digest,safe_fingerprint,state,created_at,updated_at,erased_at)
VALUES ('10000000-0000-0000-0000-000000000017','project','10000000-0000-0000-0000-000000000001','smtp_test_recipient','10000000-0000-0000-0000-000000000018',1,'configuration_secret','software',1,1,decode(repeat('09',32),'hex'),decode(repeat('0a',32),'hex'),'erased',transaction_timestamp()-interval '2 days',transaction_timestamp()-interval '2 days',transaction_timestamp()-interval '2 days');
INSERT INTO project_smtp_test_operations
(id,project_id,idempotency_key,configuration_id,configuration_generation,configuration_revision,configuration_security_eligibility_revision,host,port,tls_mode,sender_address,request_digest,message_id,recipient_erased_at,state,safe_outcome,attempts,correlation_id,created_at,expires_at,completed_at,credential_material_id,recipient_material_id)
VALUES ('10000000-0000-0000-0000-000000000018','10000000-0000-0000-0000-000000000001','smtp-test-retention','10000000-0000-0000-0000-000000000016',1,1,1,'smtp.example.com',465,'implicit_tls','login@example.com',decode(repeat('0b',32),'hex'),'<retention@runtime-test.owlauth.invalid>',transaction_timestamp()-interval '2 days','delivered','delivered',1,'10000000-0000-0000-0000-000000000019',transaction_timestamp()-interval '2 days',transaction_timestamp()-interval '2 days'+interval '10 minutes',transaction_timestamp()-interval '2 days','10000000-0000-0000-0000-000000000015','10000000-0000-0000-0000-000000000017');
COMMIT;

INSERT INTO application_user_events
(id,event_id,project_id,application_id,binding_id,user_id,event_type,user_revision,projection_revision,projection_schema,safe_body,canonical_body_digest,occurred_at,replay_until,retain_until,created_at)
VALUES ('10000000-0000-0000-0000-000000000008','evt_retention','10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000007','10000000-0000-0000-0000-000000000005','user.projection.updated',1,1,'owlauth.user.v1',jsonb_build_object('data',jsonb_build_object('projection',jsonb_build_object('verified_email',NULL))),decode(repeat('00',32),'hex'),transaction_timestamp()-interval '31 days',transaction_timestamp()-interval '2 days',transaction_timestamp()-interval '1 day',transaction_timestamp()-interval '31 days');
INSERT INTO webhook_endpoints
(id,project_id,application_id,public_id,idempotency_key,secret_request_fingerprint,url,subscribed_event_types,status,revision,created_at,updated_at)
VALUES ('10000000-0000-0000-0000-000000000009','10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002','whk_retention','endpoint-retention',decode(repeat('01',32),'hex'),'https://receiver.example.test/owlauth',ARRAY['user.projection.updated'],'pending',1,transaction_timestamp()-interval '31 days',transaction_timestamp()-interval '31 days');
INSERT INTO webhook_application_dispatch_state (project_id,application_id,last_claim_sequence)
VALUES ('10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002',0);
INSERT INTO webhook_deliveries
(id,project_id,application_id,endpoint_id,event_id,replay_sequence,state,attempt_count,next_attempt_at,lease_generation,last_outcome_class,last_http_status,created_at,updated_at,delivered_at)
VALUES ('10000000-0000-0000-0000-000000000010','10000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000009','10000000-0000-0000-0000-000000000008',0,'delivered',1,transaction_timestamp()-interval '30 days',1,'success',200,transaction_timestamp()-interval '30 days',transaction_timestamp()-interval '30 days',transaction_timestamp()-interval '30 days');
INSERT INTO webhook_delivery_attempts
(delivery_id,attempt_number,lease_generation,attempted_at,attempt_timestamp,outcome_class,http_status,duration_millis,correlation_id)
VALUES ('10000000-0000-0000-0000-000000000010',1,1,transaction_timestamp()-interval '30 days',1,'success',200,10,'10000000-0000-0000-0000-000000000011');
