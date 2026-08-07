-- OwlAuth clean baseline: keys, constraints, indexes, and triggers.



--
-- Name: application_email_assignments application_email_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_email_assignments
    ADD CONSTRAINT application_email_assignments_pkey PRIMARY KEY (project_id, application_id);


--
-- Name: application_origins application_origins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_origins
    ADD CONSTRAINT application_origins_pkey PRIMARY KEY (project_id, application_id, origin);


--
-- Name: application_provider_assignments application_provider_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_provider_assignments
    ADD CONSTRAINT application_provider_assignments_pkey PRIMARY KEY (project_id, application_id, provider_id);


--
-- Name: application_publishable_keys application_publishable_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_publishable_keys
    ADD CONSTRAINT application_publishable_keys_pkey PRIMARY KEY (id);


--
-- Name: application_publishable_keys application_publishable_keys_project_id_application_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_publishable_keys
    ADD CONSTRAINT application_publishable_keys_project_id_application_id_id_key UNIQUE (project_id, application_id, id);


--
-- Name: application_publishable_keys application_publishable_keys_project_id_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_publishable_keys
    ADD CONSTRAINT application_publishable_keys_project_id_public_id_key UNIQUE (project_id, public_id);


--
-- Name: application_redirects application_redirects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_redirects
    ADD CONSTRAINT application_redirects_pkey PRIMARY KEY (project_id, application_id, redirect_uri);


--
-- Name: application_sessions application_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_sessions
    ADD CONSTRAINT application_sessions_pkey PRIMARY KEY (id);


--
-- Name: application_sessions application_sessions_project_id_id_application_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_sessions
    ADD CONSTRAINT application_sessions_project_id_id_application_id_user_id_key UNIQUE (project_id, id, application_id, user_id);


--
-- Name: application_sessions application_sessions_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_sessions
    ADD CONSTRAINT application_sessions_project_id_id_key UNIQUE (project_id, id);


--
-- Name: application_user_bindings application_user_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_bindings
    ADD CONSTRAINT application_user_bindings_pkey PRIMARY KEY (id);


--
-- Name: application_user_bindings application_user_bindings_project_id_application_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_bindings
    ADD CONSTRAINT application_user_bindings_project_id_application_id_user_id_key UNIQUE (project_id, application_id, user_id);


--
-- Name: application_user_bindings application_user_bindings_project_id_id_application_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_bindings
    ADD CONSTRAINT application_user_bindings_project_id_id_application_id_key UNIQUE (project_id, id, application_id);


--
-- Name: application_user_bindings application_user_bindings_project_id_id_application_id_user_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_bindings
    ADD CONSTRAINT application_user_bindings_project_id_id_application_id_user_key UNIQUE (project_id, id, application_id, user_id);


--
-- Name: application_user_bindings application_user_bindings_project_id_id_application_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_bindings
    ADD CONSTRAINT application_user_bindings_project_id_id_application_unique UNIQUE (project_id, id, application_id);


--
-- Name: application_user_bindings application_user_bindings_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_bindings
    ADD CONSTRAINT application_user_bindings_project_id_id_key UNIQUE (project_id, id);


--
-- Name: application_user_events application_user_events_event_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_events
    ADD CONSTRAINT application_user_events_event_id_key UNIQUE (event_id);


--
-- Name: application_user_events application_user_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_events
    ADD CONSTRAINT application_user_events_pkey PRIMARY KEY (id);


--
-- Name: application_user_events application_user_events_project_id_application_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_events
    ADD CONSTRAINT application_user_events_project_id_application_id_id_key UNIQUE (project_id, application_id, id);


--
-- Name: application_user_projections application_user_projections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_projections
    ADD CONSTRAINT application_user_projections_pkey PRIMARY KEY (id);


--
-- Name: application_user_projections application_user_projections_project_id_binding_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_projections
    ADD CONSTRAINT application_user_projections_project_id_binding_id_key UNIQUE (project_id, binding_id);


--
-- Name: application_user_projections application_user_projections_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_projections
    ADD CONSTRAINT application_user_projections_project_id_id_key UNIQUE (project_id, id);


--
-- Name: application_user_projections application_user_projections_safe_document_check; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.application_user_projections
    ADD CONSTRAINT application_user_projections_safe_document_check CHECK (((schema_name = 'owlauth.user.v1'::text) AND (jsonb_typeof(document) = 'object'::text) AND (((document ->> 'projection_schema'::text) = 'owlauth.user.v1'::text) IS TRUE) AND (((document ?& ARRAY['user_id'::text, 'user_revision'::text, 'projection_schema'::text, 'projection_revision'::text, 'display_name'::text, 'picture_url'::text, 'locale'::text, 'verified_email'::text, 'status'::text, 'created_at'::text, 'updated_at'::text]) AND ((document - ARRAY['user_id'::text, 'user_revision'::text, 'projection_schema'::text, 'projection_revision'::text, 'display_name'::text, 'picture_url'::text, 'locale'::text, 'verified_email'::text, 'status'::text, 'created_at'::text, 'updated_at'::text]) = '{}'::jsonb) AND ((document -> 'verified_email'::text) = 'null'::jsonb)) OR ((document ?& ARRAY['user_id'::text, 'user_revision'::text, 'projection_schema'::text, 'projection_revision'::text, 'display_name'::text, 'picture_url'::text, 'status'::text, 'created_at'::text, 'updated_at'::text]) AND ((document - ARRAY['user_id'::text, 'user_revision'::text, 'projection_schema'::text, 'projection_revision'::text, 'display_name'::text, 'picture_url'::text, 'status'::text, 'created_at'::text, 'updated_at'::text]) = '{}'::jsonb)))));


--
-- Name: application_user_projections application_user_projections_source_digest_check; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.application_user_projections
    ADD CONSTRAINT application_user_projections_source_digest_check CHECK ((octet_length(source_base_profile_digest) = 32));


--
-- Name: applications applications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_pkey PRIMARY KEY (id);


--
-- Name: applications applications_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_project_id_id_key UNIQUE (project_id, id);


--
-- Name: applications applications_project_id_id_security_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_project_id_id_security_unique UNIQUE (project_id, id, security_revision);


--
-- Name: applications applications_project_id_id_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_project_id_id_unique UNIQUE (project_id, id);


--
-- Name: applications applications_project_id_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_project_id_public_id_key UNIQUE (project_id, public_id);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);


--
-- Name: server_key_digest_readiness server_key_digest_readiness_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.server_key_digest_readiness
    ADD CONSTRAINT server_key_digest_readiness_pkey PRIMARY KEY (process_id);


--
-- Name: control_idempotency_records control_idempotency_records_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.control_idempotency_records
    ADD CONSTRAINT control_idempotency_records_pkey PRIMARY KEY (idempotency_key);


--
-- Name: deployment_smtp_generations deployment_smtp_credential_material_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_smtp_generations
    ADD CONSTRAINT deployment_smtp_credential_material_uq UNIQUE (credential_material_id);


--
-- Name: deployment_smtp_generations deployment_smtp_generations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_smtp_generations
    ADD CONSTRAINT deployment_smtp_generations_pkey PRIMARY KEY (generation);


--
-- Name: deployment_smtp_generations deployment_smtp_material_owner_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_smtp_generations
    ADD CONSTRAINT deployment_smtp_material_owner_uq UNIQUE (material_owner_id);


--
-- Name: deployment_smtp_secret_operations deployment_smtp_secret_operations_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_smtp_secret_operations
    ADD CONSTRAINT deployment_smtp_secret_operations_generation_key UNIQUE (generation);


--
-- Name: deployment_smtp_secret_operations deployment_smtp_secret_operations_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_smtp_secret_operations
    ADD CONSTRAINT deployment_smtp_secret_operations_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: deployment_smtp_secret_operations deployment_smtp_secret_operations_material_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_smtp_secret_operations
    ADD CONSTRAINT deployment_smtp_secret_operations_material_id_key UNIQUE (material_id);


--
-- Name: deployment_smtp_secret_operations deployment_smtp_secret_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_smtp_secret_operations
    ADD CONSTRAINT deployment_smtp_secret_operations_pkey PRIMARY KEY (id);


--
-- Name: email_challenges email_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_challenges
    ADD CONSTRAINT email_challenges_pkey PRIMARY KEY (id);


--
-- Name: email_challenges email_challenges_project_id_id_generation_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_challenges
    ADD CONSTRAINT email_challenges_project_id_id_generation_unique UNIQUE (project_id, id, generation);


--
-- Name: email_challenges email_challenges_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_challenges
    ADD CONSTRAINT email_challenges_project_id_id_key UNIQUE (project_id, id);


--
-- Name: email_challenges email_challenges_project_id_transaction_id_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_challenges
    ADD CONSTRAINT email_challenges_project_id_transaction_id_generation_key UNIQUE (project_id, transaction_id, generation);


--
-- Name: email_identities email_identities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_identities
    ADD CONSTRAINT email_identities_pkey PRIMARY KEY (id);


--
-- Name: email_identities email_identities_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_identities
    ADD CONSTRAINT email_identities_project_id_id_key UNIQUE (project_id, id);


--
-- Name: email_identities email_identities_project_id_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_identities
    ADD CONSTRAINT email_identities_project_id_id_user_id_key UNIQUE (project_id, id, user_id);


--
-- Name: email_identity_alias_authority_events email_identity_alias_authority_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_identity_alias_authority_events
    ADD CONSTRAINT email_identity_alias_authority_events_pkey PRIMARY KEY (id);


--
-- Name: email_identity_alias_authority email_identity_alias_authority_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_identity_alias_authority
    ADD CONSTRAINT email_identity_alias_authority_pkey PRIMARY KEY (singleton);


--
-- Name: email_identity_alias_runtime_observations email_identity_alias_runtime_observations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_identity_alias_runtime_observations
    ADD CONSTRAINT email_identity_alias_runtime_observations_pkey PRIMARY KEY (process_id);


--
-- Name: email_identity_aliases email_identity_aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_identity_aliases
    ADD CONSTRAINT email_identity_aliases_pkey PRIMARY KEY (project_id, identity_id, canonicalization_version, digest_key_version);


--
-- Name: email_identity_aliases email_identity_aliases_project_id_canonicalization_version__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_identity_aliases
    ADD CONSTRAINT email_identity_aliases_project_id_canonicalization_version__key UNIQUE (project_id, canonicalization_version, digest_key_version, lookup_digest);


--
-- Name: email_protection_runtime_readiness email_protection_runtime_readiness_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_protection_runtime_readiness
    ADD CONSTRAINT email_protection_runtime_readiness_pkey PRIMARY KEY (process_id);


--
-- Name: handoff_tickets handoff_tickets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.handoff_tickets
    ADD CONSTRAINT handoff_tickets_pkey PRIMARY KEY (id);


--
-- Name: handoff_tickets handoff_tickets_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.handoff_tickets
    ADD CONSTRAINT handoff_tickets_project_id_id_key UNIQUE (project_id, id);


--
-- Name: handoff_tickets handoff_tickets_project_id_login_transaction_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.handoff_tickets
    ADD CONSTRAINT handoff_tickets_project_id_login_transaction_id_key UNIQUE (project_id, login_transaction_id);


--
-- Name: handoff_tickets handoff_tickets_ticket_digest_key_version_ticket_digest_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.handoff_tickets
    ADD CONSTRAINT handoff_tickets_ticket_digest_key_version_ticket_digest_key UNIQUE (ticket_digest_key_version, ticket_digest);


--
-- Name: identity_mutation_candidate_evidence identity_mutation_candidate_e_project_id_intent_id_slot_id__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_candidate_evidence
    ADD CONSTRAINT identity_mutation_candidate_e_project_id_intent_id_slot_id__key UNIQUE (project_id, intent_id, slot_id, id);


--
-- Name: identity_mutation_candidate_evidence identity_mutation_candidate_ev_project_id_intent_id_slot_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_candidate_evidence
    ADD CONSTRAINT identity_mutation_candidate_ev_project_id_intent_id_slot_id_key UNIQUE (project_id, intent_id, slot_id);


--
-- Name: identity_mutation_candidate_evidence identity_mutation_candidate_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_candidate_evidence
    ADD CONSTRAINT identity_mutation_candidate_evidence_pkey PRIMARY KEY (id);


--
-- Name: identity_mutation_candidate_evidence identity_mutation_candidate_evidence_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_candidate_evidence
    ADD CONSTRAINT identity_mutation_candidate_evidence_project_id_id_key UNIQUE (project_id, id);


--
-- Name: identity_mutation_create_results identity_mutation_create_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_create_results
    ADD CONSTRAINT identity_mutation_create_results_pkey PRIMARY KEY (idempotency_key);


--
-- Name: identity_mutation_create_results identity_mutation_create_results_project_id_intent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_create_results
    ADD CONSTRAINT identity_mutation_create_results_project_id_intent_id_key UNIQUE (project_id, intent_id);


--
-- Name: identity_mutation_intents identity_mutation_intents_hosted_handle_digest_key_version__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_intents
    ADD CONSTRAINT identity_mutation_intents_hosted_handle_digest_key_version__key UNIQUE (hosted_handle_digest_key_version, hosted_handle_digest);


--
-- Name: identity_mutation_intents identity_mutation_intents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_intents
    ADD CONSTRAINT identity_mutation_intents_pkey PRIMARY KEY (id);


--
-- Name: identity_mutation_intents identity_mutation_intents_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_intents
    ADD CONSTRAINT identity_mutation_intents_project_id_id_key UNIQUE (project_id, id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_pkey PRIMARY KEY (id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_id_key UNIQUE (project_id, id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_intent_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_intent_id_id_key UNIQUE (project_id, intent_id, id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_intent_id_slot_ord_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_intent_id_slot_ord_key UNIQUE (project_id, intent_id, slot_ordinal);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_intent_id_slot_rol_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_intent_id_slot_rol_key UNIQUE (project_id, intent_id, slot_role);


--
-- Name: identity_proof_receipts identity_proof_receipts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_proof_receipts
    ADD CONSTRAINT identity_proof_receipts_pkey PRIMARY KEY (id);


--
-- Name: identity_proof_receipts identity_proof_receipts_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_proof_receipts
    ADD CONSTRAINT identity_proof_receipts_project_id_id_key UNIQUE (project_id, id);


--
-- Name: identity_proof_receipts identity_proof_receipts_project_id_intent_id_slot_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_proof_receipts
    ADD CONSTRAINT identity_proof_receipts_project_id_intent_id_slot_id_key UNIQUE (project_id, intent_id, slot_id);


--
-- Name: identity_proof_receipts identity_proof_receipts_receipt_digest_key_version_receipt__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_proof_receipts
    ADD CONSTRAINT identity_proof_receipts_receipt_digest_key_version_receipt__key UNIQUE (receipt_digest_key_version, receipt_digest);


--
-- Name: key_provisioning_operations key_provisioning_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_provisioning_operations
    ADD CONSTRAINT key_provisioning_operations_pkey PRIMARY KEY (id);


--
-- Name: key_provisioning_operations key_provisioning_operations_project_id_key_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_provisioning_operations
    ADD CONSTRAINT key_provisioning_operations_project_id_key_id_key UNIQUE (project_id, key_id);


--
-- Name: key_provisioning_operations key_provisioning_operations_project_id_operation_alias_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_provisioning_operations
    ADD CONSTRAINT key_provisioning_operations_project_id_operation_alias_key UNIQUE (project_id, operation_alias);


--
-- Name: key_state_events key_state_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_state_events
    ADD CONSTRAINT key_state_events_pkey PRIMARY KEY (id);


--
-- Name: key_state_events key_state_events_project_id_signing_key_id_ring_revision_to_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_state_events
    ADD CONSTRAINT key_state_events_project_id_signing_key_id_ring_revision_to_key UNIQUE (project_id, signing_key_id, ring_revision, to_state);


--
-- Name: linked_identities linked_identities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.linked_identities
    ADD CONSTRAINT linked_identities_pkey PRIMARY KEY (id);


--
-- Name: linked_identities linked_identities_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.linked_identities
    ADD CONSTRAINT linked_identities_project_id_id_key UNIQUE (project_id, id);


--
-- Name: linked_identities linked_identities_project_id_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.linked_identities
    ADD CONSTRAINT linked_identities_project_id_id_user_id_key UNIQUE (project_id, id, user_id);


--
-- Name: linked_identities linked_identities_project_id_issuer_subject_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.linked_identities
    ADD CONSTRAINT linked_identities_project_id_issuer_subject_key UNIQUE (project_id, issuer, subject);


--
-- Name: linked_identities linked_identities_source_kind_check; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.linked_identities
    ADD CONSTRAINT linked_identities_source_kind_check CHECK ((source_kind = 'provider'::text));


--
-- Name: linked_identities linked_identities_source_profile_shape_check; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.linked_identities
    ADD CONSTRAINT linked_identities_source_profile_shape_check CHECK (((octet_length(source_profile_digest) = 32) AND ((locale IS NULL) OR ((char_length(locale) >= 2) AND (char_length(locale) <= 35)))));


--
-- Name: linked_identities linked_identities_source_schema_check; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.linked_identities
    ADD CONSTRAINT linked_identities_source_schema_check CHECK ((source_schema = 'owlauth.provider-profile.v1'::text));


--
-- Name: login_email_method_snapshots login_email_method_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_email_method_snapshots
    ADD CONSTRAINT login_email_method_snapshots_pkey PRIMARY KEY (project_id, transaction_id);


--
-- Name: login_transaction_methods login_transaction_methods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_transaction_methods
    ADD CONSTRAINT login_transaction_methods_pkey PRIMARY KEY (project_id, transaction_id, method_key);


--
-- Name: login_transactions login_transactions_interaction_digest_key_version_interacti_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_transactions
    ADD CONSTRAINT login_transactions_interaction_digest_key_version_interacti_key UNIQUE (interaction_digest_key_version, interaction_digest);


--
-- Name: login_transactions login_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_transactions
    ADD CONSTRAINT login_transactions_pkey PRIMARY KEY (id);


--
-- Name: login_transactions login_transactions_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_transactions
    ADD CONSTRAINT login_transactions_project_id_id_key UNIQUE (project_id, id);


--
-- Name: magic_transfer_contexts magic_transfer_contexts_context_digest_key_version_context__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.magic_transfer_contexts
    ADD CONSTRAINT magic_transfer_contexts_context_digest_key_version_context__key UNIQUE (context_digest_key_version, context_digest);


--
-- Name: magic_transfer_contexts magic_transfer_contexts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.magic_transfer_contexts
    ADD CONSTRAINT magic_transfer_contexts_pkey PRIMARY KEY (id);


--
-- Name: mail_outbox mail_outbox_message_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_outbox
    ADD CONSTRAINT mail_outbox_message_id_key UNIQUE (message_id);


--
-- Name: mail_outbox mail_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_outbox
    ADD CONSTRAINT mail_outbox_pkey PRIMARY KEY (id);


--
-- Name: mail_outbox mail_outbox_project_id_challenge_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_outbox
    ADD CONSTRAINT mail_outbox_project_id_challenge_id_key UNIQUE (project_id, challenge_id);


--
-- Name: mail_outbox mail_outbox_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_outbox
    ADD CONSTRAINT mail_outbox_project_id_id_key UNIQUE (project_id, id);


--
-- Name: managed_provider_claim_fairness managed_provider_claim_fairness_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_claim_fairness
    ADD CONSTRAINT managed_provider_claim_fairness_pkey PRIMARY KEY (project_id, provider_configuration_id, queue_kind);


--
-- Name: managed_provider_connections managed_provider_connections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_connections
    ADD CONSTRAINT managed_provider_connections_pkey PRIMARY KEY (id);


--
-- Name: managed_provider_connections managed_provider_connections_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_connections
    ADD CONSTRAINT managed_provider_connections_project_id_id_key UNIQUE (project_id, id);


--
-- Name: managed_provider_connections managed_provider_connections_project_id_linked_identity_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_connections
    ADD CONSTRAINT managed_provider_connections_project_id_linked_identity_id_key UNIQUE (project_id, linked_identity_id);


--
-- Name: managed_provider_credentials managed_provider_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_credentials
    ADD CONSTRAINT managed_provider_credentials_pkey PRIMARY KEY (project_id, connection_id, credential_generation);


--
-- Name: managed_provider_reauthorization_interactions managed_provider_reauthorizat_interaction_digest_key_versio_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_provider_reauthorizat_interaction_digest_key_versio_key UNIQUE (interaction_digest_key_version, interaction_digest);


--
-- Name: managed_provider_reauthorization_interactions managed_provider_reauthorization_interactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_provider_reauthorization_interactions_pkey PRIMARY KEY (id);


--
-- Name: managed_provider_reauthorization_interactions managed_provider_reauthorization_interactions_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_provider_reauthorization_interactions_project_id_id_key UNIQUE (project_id, id);


--
-- Name: managed_provider_renewal_operations managed_provider_renewal_oper_project_id_connection_id_atte_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_renewal_operations
    ADD CONSTRAINT managed_provider_renewal_oper_project_id_connection_id_atte_key UNIQUE (project_id, connection_id, attempt_id);


--
-- Name: managed_provider_renewal_operations managed_provider_renewal_oper_project_id_connection_id_expe_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_renewal_operations
    ADD CONSTRAINT managed_provider_renewal_oper_project_id_connection_id_expe_key UNIQUE (project_id, connection_id, expected_connection_generation);


--
-- Name: managed_provider_renewal_operations managed_provider_renewal_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_renewal_operations
    ADD CONSTRAINT managed_provider_renewal_operations_pkey PRIMARY KEY (id);


--
-- Name: managed_provider_renewal_operations managed_provider_renewal_operations_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_renewal_operations
    ADD CONSTRAINT managed_provider_renewal_operations_project_id_id_key UNIQUE (project_id, id);


--
-- Name: managed_reauthorization_create_results managed_reauthorization_create_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_reauthorization_create_results
    ADD CONSTRAINT managed_reauthorization_create_results_pkey PRIMARY KEY (idempotency_key);


--
-- Name: project_browser_logout_interactions project_browser_logout_intera_preparation_digest_key_versio_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_browser_logout_interactions
    ADD CONSTRAINT project_browser_logout_intera_preparation_digest_key_versio_key UNIQUE (preparation_digest_key_version, preparation_digest);


--
-- Name: project_browser_logout_interactions project_browser_logout_interactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_browser_logout_interactions
    ADD CONSTRAINT project_browser_logout_interactions_pkey PRIMARY KEY (id);


--
-- Name: project_browser_logout_interactions project_browser_logout_interactions_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_browser_logout_interactions
    ADD CONSTRAINT project_browser_logout_interactions_project_id_id_key UNIQUE (project_id, id);


--
-- Name: project_browser_sessions project_browser_sessions_credential_digest_key_version_cred_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_browser_sessions
    ADD CONSTRAINT project_browser_sessions_credential_digest_key_version_cred_key UNIQUE (credential_digest_key_version, credential_digest);


--
-- Name: project_browser_sessions project_browser_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_browser_sessions
    ADD CONSTRAINT project_browser_sessions_pkey PRIMARY KEY (id);


--
-- Name: project_browser_sessions project_browser_sessions_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_browser_sessions
    ADD CONSTRAINT project_browser_sessions_project_id_id_key UNIQUE (project_id, id);


--
-- Name: project_browser_sessions project_browser_sessions_project_id_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_browser_sessions
    ADD CONSTRAINT project_browser_sessions_project_id_id_user_id_key UNIQUE (project_id, id, user_id);


--
-- Name: project_server_keys project_server_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_server_keys
    ADD CONSTRAINT project_server_keys_pkey PRIMARY KEY (id);


--
-- Name: project_server_keys project_server_keys_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_server_keys
    ADD CONSTRAINT project_server_keys_project_id_id_key UNIQUE (project_id, id);


--
-- Name: project_server_keys project_server_keys_public_key_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_server_keys
    ADD CONSTRAINT project_server_keys_public_key_id_key UNIQUE (public_key_id);


--
-- Name: project_email_policies project_email_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_email_policies
    ADD CONSTRAINT project_email_policies_pkey PRIMARY KEY (project_id);


--
-- Name: project_key_rings project_key_rings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_key_rings
    ADD CONSTRAINT project_key_rings_pkey PRIMARY KEY (id);


--
-- Name: project_key_rings project_key_rings_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_key_rings
    ADD CONSTRAINT project_key_rings_project_id_id_key UNIQUE (project_id, id);


--
-- Name: project_key_rings project_key_rings_project_id_issuer_purpose_algorithm_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_key_rings
    ADD CONSTRAINT project_key_rings_project_id_issuer_purpose_algorithm_key UNIQUE (project_id, issuer, purpose, algorithm);


--
-- Name: project_policies project_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_policies
    ADD CONSTRAINT project_policies_pkey PRIMARY KEY (project_id);


--
-- Name: project_provider_egress_policies project_provider_egress_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_provider_egress_policies
    ADD CONSTRAINT project_provider_egress_policies_pkey PRIMARY KEY (project_id);


--
-- Name: project_signing_keys project_signing_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_signing_keys
    ADD CONSTRAINT project_signing_keys_pkey PRIMARY KEY (id);


--
-- Name: project_signing_keys project_signing_keys_project_id_kid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_signing_keys
    ADD CONSTRAINT project_signing_keys_project_id_kid_key UNIQUE (project_id, kid);


--
-- Name: project_signing_keys project_signing_keys_project_id_ring_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_signing_keys
    ADD CONSTRAINT project_signing_keys_project_id_ring_id_id_key UNIQUE (project_id, ring_id, id);


--
-- Name: project_smtp_configurations project_smtp_configurations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_configurations
    ADD CONSTRAINT project_smtp_configurations_pkey PRIMARY KEY (id);


--
-- Name: project_smtp_configurations project_smtp_configurations_project_id_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_configurations
    ADD CONSTRAINT project_smtp_configurations_project_id_generation_key UNIQUE (project_id, generation);


--
-- Name: project_smtp_configurations project_smtp_configurations_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_configurations
    ADD CONSTRAINT project_smtp_configurations_project_id_id_key UNIQUE (project_id, id);


--
-- Name: project_smtp_configurations project_smtp_credential_material_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_configurations
    ADD CONSTRAINT project_smtp_credential_material_uq UNIQUE (credential_material_id);


--
-- Name: project_smtp_configurations project_smtp_material_owner_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_configurations
    ADD CONSTRAINT project_smtp_material_owner_uq UNIQUE (project_id, id, credential_material_id);


--
-- Name: project_smtp_configurations project_smtp_material_scope_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_configurations
    ADD CONSTRAINT project_smtp_material_scope_uq UNIQUE (project_id, id, generation, credential_material_id);


--
-- Name: project_smtp_runtime_readiness project_smtp_runtime_readiness_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_runtime_readiness
    ADD CONSTRAINT project_smtp_runtime_readiness_pkey PRIMARY KEY (project_id, configuration_id, generation, process_id);


--
-- Name: project_smtp_secret_operations project_smtp_secret_material_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_secret_operations
    ADD CONSTRAINT project_smtp_secret_material_uq UNIQUE (material_id);


--
-- Name: project_smtp_secret_operations project_smtp_secret_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_secret_operations
    ADD CONSTRAINT project_smtp_secret_operations_pkey PRIMARY KEY (project_id, operation_alias);


--
-- Name: project_smtp_test_operations project_smtp_test_operations_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_test_operations
    ADD CONSTRAINT project_smtp_test_operations_id_key UNIQUE (id);


--
-- Name: project_smtp_test_operations project_smtp_test_operations_message_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_test_operations
    ADD CONSTRAINT project_smtp_test_operations_message_id_key UNIQUE (message_id);


--
-- Name: project_smtp_test_operations project_smtp_test_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_test_operations
    ADD CONSTRAINT project_smtp_test_operations_pkey PRIMARY KEY (project_id, idempotency_key);


--
-- Name: project_smtp_test_operations project_smtp_test_recipient_material_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_test_operations
    ADD CONSTRAINT project_smtp_test_recipient_material_uq UNIQUE (recipient_material_id);


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_intent_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_user_merge_tombstones
    ADD CONSTRAINT project_user_merge_tombstones_intent_unique UNIQUE (project_id, identity_mutation_intent_id);


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_user_merge_tombstones
    ADD CONSTRAINT project_user_merge_tombstones_pkey PRIMARY KEY (project_id, loser_user_id);


--
-- Name: project_users project_users_local_profile_shape_check; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.project_users
    ADD CONSTRAINT project_users_local_profile_shape_check CHECK (((local_display_name_set OR (local_display_name IS NULL)) AND (local_picture_url_set OR (local_picture_url IS NULL)) AND (local_locale_set OR (local_locale IS NULL)) AND ((local_display_name IS NULL) OR ((char_length(local_display_name) >= 1) AND (char_length(local_display_name) <= 128))) AND ((local_picture_url IS NULL) OR ((char_length(local_picture_url) >= 8) AND (char_length(local_picture_url) <= 2048))) AND ((local_locale IS NULL) OR ((char_length(local_locale) >= 2) AND (char_length(local_locale) <= 35))) AND ((locale IS NULL) OR ((char_length(locale) >= 2) AND (char_length(locale) <= 35)))));


--
-- Name: project_users project_users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_users
    ADD CONSTRAINT project_users_pkey PRIMARY KEY (id);


--
-- Name: project_users project_users_primary_source_kind_check; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.project_users
    ADD CONSTRAINT project_users_primary_source_kind_check CHECK ((primary_source_kind = ANY (ARRAY['provider'::text, 'email'::text])));


--
-- Name: project_users project_users_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_users
    ADD CONSTRAINT project_users_project_id_id_key UNIQUE (project_id, id);


--
-- Name: project_users project_users_project_id_id_security_revision_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_users
    ADD CONSTRAINT project_users_project_id_id_security_revision_key UNIQUE (project_id, id, security_revision);


--
-- Name: project_users project_users_project_id_id_user_revision_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_users
    ADD CONSTRAINT project_users_project_id_id_user_revision_key UNIQUE (project_id, id, user_revision);


--
-- Name: project_users project_users_project_id_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_users
    ADD CONSTRAINT project_users_project_id_public_id_key UNIQUE (project_id, public_id);


--
-- Name: projection_email_key_authority projection_email_key_authority_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projection_email_key_authority
    ADD CONSTRAINT projection_email_key_authority_pkey PRIMARY KEY (singleton);


--
-- Name: projection_email_runtime_observations projection_email_runtime_observations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projection_email_runtime_observations
    ADD CONSTRAINT projection_email_runtime_observations_pkey PRIMARY KEY (process_id, process_incarnation);


--
-- Name: projects projects_id_metadata_revision_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_id_metadata_revision_key UNIQUE (id, metadata_revision);


--
-- Name: projects projects_id_revision_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_id_revision_unique UNIQUE (id, metadata_revision, security_revision);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: projects projects_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_public_id_key UNIQUE (public_id);


--
-- Name: protected_material_inventory_authority protected_material_inventory_authority_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protected_material_inventory_authority
    ADD CONSTRAINT protected_material_inventory_authority_pkey PRIMARY KEY (singleton);


--
-- Name: protected_materials protected_materials_id_owner_kind_owner_id_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protected_materials
    ADD CONSTRAINT protected_materials_id_owner_kind_owner_id_generation_key UNIQUE (id, owner_kind, owner_id, generation);


--
-- Name: protected_materials protected_materials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protected_materials
    ADD CONSTRAINT protected_materials_pkey PRIMARY KEY (id);


--
-- Name: protected_materials protected_materials_scope_kind_project_id_owner_kind_owner__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protected_materials
    ADD CONSTRAINT protected_materials_scope_kind_project_id_owner_kind_owner__key UNIQUE NULLS NOT DISTINCT (scope_kind, project_id, owner_kind, owner_id, generation);


--
-- Name: provider_callback_owners provider_callback_owners_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_callback_owners
    ADD CONSTRAINT provider_callback_owners_pkey PRIMARY KEY (state_id);


--
-- Name: provider_callback_owners provider_callback_owners_project_id_state_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_callback_owners
    ADD CONSTRAINT provider_callback_owners_project_id_state_id_key UNIQUE (project_id, state_id);


--
-- Name: provider_configurations provider_configurations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_configurations
    ADD CONSTRAINT provider_configurations_pkey PRIMARY KEY (id);


--
-- Name: provider_configurations provider_configurations_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_configurations
    ADD CONSTRAINT provider_configurations_project_id_id_key UNIQUE (project_id, id);


--
-- Name: provider_configurations provider_configurations_project_id_provider_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_configurations
    ADD CONSTRAINT provider_configurations_project_id_provider_key_key UNIQUE (project_id, provider_key);


--
-- Name: provider_secret_operations provider_secret_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_secret_operations
    ADD CONSTRAINT provider_secret_operations_pkey PRIMARY KEY (id);


--
-- Name: provider_secret_operations provider_secret_operations_project_id_operation_alias_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_secret_operations
    ADD CONSTRAINT provider_secret_operations_project_id_operation_alias_key UNIQUE (project_id, operation_alias);


--
-- Name: provider_secret_operations provider_secret_operations_project_id_provider_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_secret_operations
    ADD CONSTRAINT provider_secret_operations_project_id_provider_id_key UNIQUE (project_id, provider_id);


--
-- Name: refresh_families refresh_families_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_families
    ADD CONSTRAINT refresh_families_pkey PRIMARY KEY (id);


--
-- Name: refresh_families refresh_families_project_id_application_session_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_families
    ADD CONSTRAINT refresh_families_project_id_application_session_id_key UNIQUE (project_id, application_session_id);


--
-- Name: refresh_families refresh_families_project_id_id_application_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_families
    ADD CONSTRAINT refresh_families_project_id_id_application_id_user_id_key UNIQUE (project_id, id, application_id, user_id);


--
-- Name: refresh_families refresh_families_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_families
    ADD CONSTRAINT refresh_families_project_id_id_key UNIQUE (project_id, id);


--
-- Name: refresh_token_generations refresh_token_generations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_token_generations
    ADD CONSTRAINT refresh_token_generations_pkey PRIMARY KEY (id);


--
-- Name: refresh_token_generations refresh_token_generations_project_id_family_id_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_token_generations
    ADD CONSTRAINT refresh_token_generations_project_id_family_id_generation_key UNIQUE (project_id, family_id, generation);


--
-- Name: refresh_token_generations refresh_token_generations_project_id_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_token_generations
    ADD CONSTRAINT refresh_token_generations_project_id_id_key UNIQUE (project_id, id);


--
-- Name: refresh_token_generations refresh_token_generations_token_digest_key_version_token_di_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_token_generations
    ADD CONSTRAINT refresh_token_generations_token_digest_key_version_token_di_key UNIQUE (token_digest_key_version, token_digest);


--
-- Name: auth_process_incarnations auth_process_incarnations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_process_incarnations
    ADD CONSTRAINT auth_process_incarnations_pkey PRIMARY KEY (process_id);


--
-- Name: auth_process_incarnations auth_process_incarnations_process_id_process_incarnation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_process_incarnations
    ADD CONSTRAINT auth_process_incarnations_process_id_process_incarnation_key UNIQUE (process_id, process_incarnation);


--
-- Name: runtime_publication_leases runtime_publication_leases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runtime_publication_leases
    ADD CONSTRAINT runtime_publication_leases_pkey PRIMARY KEY (project_id, ring_id, process_id);


--
-- Name: smtp_credential_cleanup_operations smtp_credential_cleanup_material_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smtp_credential_cleanup_operations
    ADD CONSTRAINT smtp_credential_cleanup_material_uq UNIQUE (material_id);


--
-- Name: smtp_credential_cleanup_operations smtp_credential_cleanup_operati_scope_project_id_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smtp_credential_cleanup_operations
    ADD CONSTRAINT smtp_credential_cleanup_operati_scope_project_id_generation_key UNIQUE NULLS NOT DISTINCT (scope, project_id, generation);


--
-- Name: smtp_credential_cleanup_operations smtp_credential_cleanup_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smtp_credential_cleanup_operations
    ADD CONSTRAINT smtp_credential_cleanup_operations_pkey PRIMARY KEY (id);


--
-- Name: webhook_application_dispatch_state webhook_application_dispatch_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_application_dispatch_state
    ADD CONSTRAINT webhook_application_dispatch_state_pkey PRIMARY KEY (project_id, application_id);


--
-- Name: webhook_deliveries webhook_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);


--
-- Name: webhook_deliveries webhook_deliveries_project_id_application_id_endpoint_id_ev_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_project_id_application_id_endpoint_id_ev_key UNIQUE (project_id, application_id, endpoint_id, event_id, id);


--
-- Name: webhook_delivery_attempts webhook_delivery_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_delivery_attempts
    ADD CONSTRAINT webhook_delivery_attempts_pkey PRIMARY KEY (delivery_id, attempt_number);


--
-- Name: webhook_endpoints webhook_endpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_pkey PRIMARY KEY (id);


--
-- Name: webhook_endpoints webhook_endpoints_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_public_id_key UNIQUE (public_id);


--
-- Name: webhook_endpoints webhook_endpoints_scope_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_scope_uq UNIQUE (project_id, application_id, id);


--
-- Name: webhook_secret_cleanup_operations webhook_secret_cleanup_generation_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_secret_cleanup_operations
    ADD CONSTRAINT webhook_secret_cleanup_generation_uq UNIQUE (endpoint_id, generation);


--
-- Name: webhook_secret_cleanup_operations webhook_secret_cleanup_material_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_secret_cleanup_operations
    ADD CONSTRAINT webhook_secret_cleanup_material_uq UNIQUE (material_id);


--
-- Name: webhook_secret_cleanup_operations webhook_secret_cleanup_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_secret_cleanup_operations
    ADD CONSTRAINT webhook_secret_cleanup_operations_pkey PRIMARY KEY (id);


--
-- Name: webhook_secret_generations webhook_secret_generation_material_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_secret_generations
    ADD CONSTRAINT webhook_secret_generation_material_uq UNIQUE NULLS NOT DISTINCT (endpoint_id, generation, material_id);


--
-- Name: webhook_secret_generations webhook_secret_generations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_secret_generations
    ADD CONSTRAINT webhook_secret_generations_pkey PRIMARY KEY (endpoint_id, generation);


--
-- Name: webhook_secret_generations webhook_secret_material_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_secret_generations
    ADD CONSTRAINT webhook_secret_material_uq UNIQUE (material_id);


--
-- Name: application_bindings_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_bindings_user_idx ON public.application_user_bindings USING btree (project_id, user_id, status, application_id);


--
-- Name: application_sessions_user_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_sessions_user_status_idx ON public.application_sessions USING btree (project_id, user_id, status, absolute_expires_at);


--
-- Name: application_user_events_application_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_user_events_application_time_idx ON public.application_user_events USING btree (project_id, application_id, occurred_at DESC, id DESC);


--
-- Name: application_user_events_binding_revision_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX application_user_events_binding_revision_uq ON public.application_user_events USING btree (binding_id, projection_revision);


--
-- Name: application_user_events_email_key_version_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_user_events_email_key_version_idx ON public.application_user_events USING btree (verified_email_key_version) WHERE (verified_email_key_version IS NOT NULL);


--
-- Name: application_user_events_retention_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_user_events_retention_idx ON public.application_user_events USING btree (retain_until, id);


--
-- Name: application_user_events_user_revision_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_user_events_user_revision_idx ON public.application_user_events USING btree (project_id, application_id, user_id, projection_revision DESC);


--
-- Name: application_user_projections_email_rewrap_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_user_projections_email_rewrap_idx ON public.application_user_projections USING btree (verified_email_key_version, id) WHERE (verified_email_key_version IS NOT NULL);


--
-- Name: applications_project_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX applications_project_status_idx ON public.applications USING btree (project_id, status, created_at, id);


--
-- Name: assignments_application_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX assignments_application_status_idx ON public.application_provider_assignments USING btree (project_id, application_id, status);


--
-- Name: audit_events_project_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_events_project_time_idx ON public.audit_events USING btree (project_id, occurred_at DESC, id);


--
-- Name: browser_logout_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX browser_logout_expiry_idx ON public.project_browser_logout_interactions USING btree (status, expires_at, id);


--
-- Name: browser_sessions_user_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX browser_sessions_user_status_idx ON public.project_browser_sessions USING btree (project_id, user_id, status, absolute_expires_at);


--
-- Name: server_key_digest_readiness_lease_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX server_key_digest_readiness_lease_idx ON public.server_key_digest_readiness USING btree (lease_expires_at, process_id);


--
-- Name: control_idempotency_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX control_idempotency_expiry_idx ON public.control_idempotency_records USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: deployment_smtp_one_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX deployment_smtp_one_active_idx ON public.deployment_smtp_generations USING btree ((true)) WHERE (status = 'active'::text);


--
-- Name: email_challenges_cleanup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX email_challenges_cleanup_idx ON public.email_challenges USING btree (status, expires_at, id);


--
-- Name: email_challenges_login_one_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX email_challenges_login_one_pending_idx ON public.email_challenges USING btree (project_id, transaction_id) WHERE ((owner_kind = 'login'::text) AND (status = 'pending'::text));


--
-- Name: email_challenges_mutation_generation_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX email_challenges_mutation_generation_unique_idx ON public.email_challenges USING btree (project_id, identity_mutation_intent_id, identity_mutation_proof_slot_id, generation) WHERE (owner_kind = 'identity_mutation'::text);


--
-- Name: email_challenges_mutation_one_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX email_challenges_mutation_one_pending_idx ON public.email_challenges USING btree (project_id, identity_mutation_intent_id, identity_mutation_proof_slot_id) WHERE ((owner_kind = 'identity_mutation'::text) AND (status = 'pending'::text));


--
-- Name: email_challenges_payload_retention_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX email_challenges_payload_retention_idx ON public.email_challenges USING btree (terminal_at, expires_at, id) WHERE (address_ciphertext IS NOT NULL);


--
-- Name: email_identities_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX email_identities_user_idx ON public.email_identities USING btree (project_id, user_id, status);


--
-- Name: handoff_tickets_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX handoff_tickets_expiry_idx ON public.handoff_tickets USING btree (status, expires_at, id);


--
-- Name: identity_mutation_candidate_cleanup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_mutation_candidate_cleanup_idx ON public.identity_mutation_candidate_evidence USING btree (retain_until, project_id, intent_id);


--
-- Name: identity_mutation_intents_cleanup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_mutation_intents_cleanup_idx ON public.identity_mutation_intents USING btree (status, expires_at, id) WHERE (status = ANY (ARRAY['pending_proof'::text, 'ready'::text]));


--
-- Name: identity_mutation_intents_project_users_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_mutation_intents_project_users_idx ON public.identity_mutation_intents USING btree (project_id, destination_user_id, identity_owner_user_id, winner_user_id, loser_user_id, status);


--
-- Name: identity_mutation_proof_slots_state_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_mutation_proof_slots_state_idx ON public.identity_mutation_proof_slots USING btree (project_id, intent_id, state, slot_ordinal);


--
-- Name: identity_mutation_slots_upstream_state_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX identity_mutation_slots_upstream_state_unique_idx ON public.identity_mutation_proof_slots USING btree (upstream_state_digest_key_version, upstream_state_digest) WHERE (upstream_state_digest IS NOT NULL);


--
-- Name: identity_proof_receipts_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_proof_receipts_expiry_idx ON public.identity_proof_receipts USING btree (status, expires_at, id) WHERE (status = 'issued'::text);


--
-- Name: identity_proof_receipts_intent_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_proof_receipts_intent_status_idx ON public.identity_proof_receipts USING btree (project_id, intent_id, status, expires_at, slot_id);


--
-- Name: key_provisioning_provider_recovery_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX key_provisioning_provider_recovery_idx ON public.key_provisioning_operations USING btree (state, next_attempt_at, provider_lease_expires_at, id) WHERE (state = ANY (ARRAY['submitted'::text, 'cleanup_pending'::text, 'cleanup_leased'::text]));


--
-- Name: key_state_events_key_revision_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX key_state_events_key_revision_idx ON public.key_state_events USING btree (project_id, signing_key_id, ring_revision);


--
-- Name: linked_identities_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX linked_identities_user_idx ON public.linked_identities USING btree (project_id, user_id, status);


--
-- Name: linked_identities_provider_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX linked_identities_provider_user_idx ON public.linked_identities USING btree (project_id, created_via_provider_configuration_id, user_id, status);


--
-- Name: login_transactions_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX login_transactions_expiry_idx ON public.login_transactions USING btree (status, expires_at, id);


--
-- Name: login_transactions_provider_callback_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX login_transactions_provider_callback_idx ON public.login_transactions USING btree (project_id, provider_configuration_id, status, expires_at) WHERE (provider_configuration_id IS NOT NULL);


--
-- Name: login_transactions_upstream_state_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX login_transactions_upstream_state_unique_idx ON public.login_transactions USING btree (upstream_state_digest_key_version, upstream_state_digest) WHERE (upstream_state_digest IS NOT NULL);


--
-- Name: magic_transfer_context_consumed_cleanup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX magic_transfer_context_consumed_cleanup_idx ON public.magic_transfer_contexts USING btree (consumed_at, id) WHERE (consumed_at IS NOT NULL);


--
-- Name: magic_transfer_context_expiry_cleanup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX magic_transfer_context_expiry_cleanup_idx ON public.magic_transfer_contexts USING btree (expires_at, id);


--
-- Name: mail_outbox_attempt_cleanup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_outbox_attempt_cleanup_idx ON public.mail_outbox USING btree (id) WHERE ((status = ANY (ARRAY['pending'::text, 'retry'::text, 'ambiguous'::text, 'leased'::text])) AND (attempts >= max_attempts));


--
-- Name: mail_outbox_claim_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_outbox_claim_idx ON public.mail_outbox USING btree (next_attempt_at, id) WHERE (status = ANY (ARRAY['pending'::text, 'retry'::text, 'ambiguous'::text]));


--
-- Name: mail_outbox_expiry_cleanup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_outbox_expiry_cleanup_idx ON public.mail_outbox USING btree (useful_until, id) WHERE (status = ANY (ARRAY['pending'::text, 'retry'::text, 'ambiguous'::text, 'leased'::text]));


--
-- Name: mail_outbox_payload_retention_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mail_outbox_payload_retention_idx ON public.mail_outbox USING btree (terminal_at, id) WHERE (envelope_ciphertext IS NOT NULL);


--
-- Name: managed_provider_connections_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_provider_connections_due_idx ON public.managed_provider_connections USING btree (next_synchronize_at, project_id, provider_configuration_id, id) WHERE ((state = 'active'::text) AND (next_synchronize_at IS NOT NULL));


--
-- Name: managed_provider_connections_renewal_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_provider_connections_renewal_due_idx ON public.managed_provider_connections USING btree (next_renewal_at, project_id, provider_configuration_id, id) WHERE ((state = 'active'::text) AND (next_renewal_at IS NOT NULL));


--
-- Name: managed_provider_connections_revocation_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_provider_connections_revocation_due_idx ON public.managed_provider_connections USING btree (revocation_dispatch_started_at, revocation_requested_at, project_id, provider_configuration_id, id) WHERE ((state = 'active'::text) AND (revocation_requested_at IS NOT NULL));


--
-- Name: managed_provider_credentials_live_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX managed_provider_credentials_live_idx ON public.managed_provider_credentials USING btree (project_id, connection_id) WHERE (ciphertext IS NOT NULL);


--
-- Name: managed_provider_renewal_recovery_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_provider_renewal_recovery_idx ON public.managed_provider_renewal_operations USING btree (state, lease_expires_at, project_id, connection_id) WHERE (state = ANY (ARRAY['prepared'::text, 'submitted'::text]));


--
-- Name: managed_reauthorization_state_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_reauthorization_state_idx ON public.managed_provider_reauthorization_interactions USING btree (upstream_state_key_version, upstream_state_digest) WHERE (status = ANY (ARRAY['provider_authorization_started'::text, 'provider_exchange_in_progress'::text]));


--
-- Name: project_server_keys_active_project_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_server_keys_active_project_idx ON public.project_server_keys USING btree (project_id, id) WHERE (status = 'active'::text);


--
-- Name: project_server_keys_one_unacknowledged_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX project_server_keys_one_unacknowledged_active_idx ON public.project_server_keys USING btree (project_id) WHERE ((status = 'active'::text) AND (credential_acknowledged_at IS NULL));


--
-- Name: project_server_keys_project_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_server_keys_project_created_idx ON public.project_server_keys USING btree (project_id, created_at, id);


--
-- Name: project_signing_keys_one_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX project_signing_keys_one_active_idx ON public.project_signing_keys USING btree (project_id, ring_id) WHERE (state = 'active'::text);


--
-- Name: project_signing_keys_one_pending_candidate_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX project_signing_keys_one_pending_candidate_idx ON public.project_signing_keys USING btree (project_id, ring_id) WHERE (state = ANY (ARRAY['provisioning'::text, 'published'::text]));


--
-- Name: project_smtp_one_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX project_smtp_one_active_idx ON public.project_smtp_configurations USING btree (project_id) WHERE (status = 'active'::text);


--
-- Name: project_smtp_runtime_readiness_state_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_smtp_runtime_readiness_state_idx ON public.project_smtp_runtime_readiness USING btree (state, lease_expires_at, checked_at);


--
-- Name: project_smtp_test_claim_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_smtp_test_claim_idx ON public.project_smtp_test_operations USING btree (created_at, project_id) WHERE (state = 'pending'::text);


--
-- Name: project_smtp_test_delivered_evidence_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_smtp_test_delivered_evidence_idx ON public.project_smtp_test_operations USING btree (project_id, configuration_id, configuration_generation, configuration_revision, configuration_security_eligibility_revision) WHERE ((state = 'delivered'::text) AND (safe_outcome = 'delivered'::text) AND (completed_at IS NOT NULL));


--
-- Name: project_user_merge_winner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_user_merge_winner_idx ON public.project_user_merge_tombstones USING btree (project_id, winner_user_id, merged_at);


--
-- Name: project_users_client_list_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_users_client_list_idx ON public.project_users USING btree (project_id, created_at, id);


--
-- Name: project_users_display_name_search_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_users_display_name_search_idx ON public.project_users USING btree (project_id, lower(display_name) text_pattern_ops) WHERE (display_name IS NOT NULL);


--
-- Name: project_users_public_id_search_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_users_public_id_search_idx ON public.project_users USING btree (project_id, lower(public_id) text_pattern_ops);


--
-- Name: project_users_project_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_users_project_status_idx ON public.project_users USING btree (project_id, status, created_at, id);


--
-- Name: projection_email_runtime_observations_live_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX projection_email_runtime_observations_live_idx ON public.projection_email_runtime_observations USING btree (process_id, lease_expires_at);


--
-- Name: projects_belongs_to_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX projects_belongs_to_idx ON public.projects USING btree (belongs_to) WHERE (belongs_to IS NOT NULL);


--
-- Name: protected_material_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX protected_material_pending_idx ON public.protected_materials USING btree (created_at, id) WHERE (state = 'pending'::text);


--
-- Name: protected_material_project_owner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX protected_material_project_owner_idx ON public.protected_materials USING btree (project_id, owner_kind, owner_id, generation);


--
-- Name: protected_material_provider_state_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX protected_material_provider_state_idx ON public.protected_materials USING btree (provider_id, provider_format_version, state, id);


--
-- Name: provider_callback_owners_route_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX provider_callback_owners_route_idx ON public.provider_callback_owners USING btree (project_id, provider_configuration_id, owner_kind, state_id);


--
-- Name: provider_configurations_custom_policy_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX provider_configurations_custom_policy_idx ON public.provider_configurations USING btree (project_id, onboarding_policy_revision, id) WHERE (kind = 'oidc'::text);


--
-- Name: providers_project_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX providers_project_status_idx ON public.provider_configurations USING btree (project_id, status, created_at, id);


--
-- Name: refresh_families_session_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX refresh_families_session_status_idx ON public.refresh_families USING btree (project_id, application_session_id, status);


--
-- Name: refresh_generations_one_current_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX refresh_generations_one_current_idx ON public.refresh_token_generations USING btree (project_id, family_id) WHERE (status = 'current'::text);


--
-- Name: refresh_generations_retention_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX refresh_generations_retention_idx ON public.refresh_token_generations USING btree (retain_until, id);


--
-- Name: runtime_publication_leases_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX runtime_publication_leases_expiry_idx ON public.runtime_publication_leases USING btree (project_id, ring_id, expires_at);


--
-- Name: signing_keys_project_ring_state_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX signing_keys_project_ring_state_idx ON public.project_signing_keys USING btree (project_id, ring_id, state, created_at, id);


--
-- Name: webhook_deliveries_claim_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_deliveries_claim_idx ON public.webhook_deliveries USING btree (next_attempt_at, endpoint_id, created_at, id) WHERE (state = 'pending'::text);


--
-- Name: webhook_deliveries_endpoint_history_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_deliveries_endpoint_history_idx ON public.webhook_deliveries USING btree (project_id, application_id, endpoint_id, created_at DESC, id DESC);


--
-- Name: webhook_deliveries_event_endpoint_replay_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX webhook_deliveries_event_endpoint_replay_uq ON public.webhook_deliveries USING btree (event_id, endpoint_id, replay_sequence);


--
-- Name: webhook_deliveries_expired_lease_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_deliveries_expired_lease_idx ON public.webhook_deliveries USING btree (lease_expires_at, endpoint_id, id) WHERE (state = 'leased'::text);


--
-- Name: webhook_delivery_attempts_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_delivery_attempts_time_idx ON public.webhook_delivery_attempts USING btree (attempted_at DESC, delivery_id);


--
-- Name: webhook_endpoints_active_application_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_endpoints_active_application_idx ON public.webhook_endpoints USING btree (project_id, application_id, id) WHERE (status = 'active'::text);


--
-- Name: webhook_endpoints_application_url_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX webhook_endpoints_application_url_uq ON public.webhook_endpoints USING btree (project_id, application_id, url) WHERE (status <> 'disabled'::text);


--
-- Name: webhook_endpoints_idempotency_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX webhook_endpoints_idempotency_uq ON public.webhook_endpoints USING btree (project_id, application_id, idempotency_key);


--
-- Name: webhook_secret_cleanup_claim_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_secret_cleanup_claim_idx ON public.webhook_secret_cleanup_operations USING btree (state, not_before, lease_expires_at, created_at, id) WHERE (state = ANY (ARRAY['pending'::text, 'leased'::text]));


--
-- Name: webhook_secret_idempotency_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX webhook_secret_idempotency_uq ON public.webhook_secret_generations USING btree (endpoint_id, idempotency_key);


--
-- Name: webhook_secret_one_active_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX webhook_secret_one_active_uq ON public.webhook_secret_generations USING btree (endpoint_id) WHERE (state = 'active'::text);


--
-- Name: webhook_secret_one_overlap_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX webhook_secret_one_overlap_uq ON public.webhook_secret_generations USING btree (endpoint_id) WHERE (state = 'overlap'::text);


--
-- Name: webhook_secret_one_pending_uq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX webhook_secret_one_pending_uq ON public.webhook_secret_generations USING btree (endpoint_id) WHERE (state = 'pending'::text);


--
-- Name: application_sessions application_sessions_capture_original_binding_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER application_sessions_capture_original_binding_owner BEFORE INSERT ON public.application_sessions FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_application_session_original_binding_owner();


--
-- Name: application_sessions application_sessions_stable_credential_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER application_sessions_stable_credential_owner BEFORE UPDATE ON public.application_sessions FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('id', 'project_id', 'application_id', 'binding_id', 'user_id', 'created_at');


--
-- Name: application_user_bindings application_user_bindings_exact_merge_target; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER application_user_bindings_exact_merge_target AFTER INSERT OR UPDATE OF status, user_id, merged_into_binding_id ON public.application_user_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_merged_binding_target();


--
-- Name: application_user_bindings application_user_bindings_exact_merged_user; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER application_user_bindings_exact_merged_user AFTER INSERT OR DELETE OR UPDATE OF status, user_id, merged_into_binding_id ON public.application_user_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_merged_user_binding_ownership();


--
-- Name: application_user_bindings application_user_bindings_merged_terminal; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER application_user_bindings_merged_terminal BEFORE UPDATE ON public.application_user_bindings FOR EACH ROW EXECUTE FUNCTION public.owlauth_reject_merged_binding_reopen();


--
-- Name: application_user_bindings application_user_bindings_preserve_merged_attribution; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER application_user_bindings_preserve_merged_attribution BEFORE DELETE ON public.application_user_bindings FOR EACH ROW EXECUTE FUNCTION public.owlauth_reject_merged_binding_delete();


--
-- Name: application_user_events application_user_events_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER application_user_events_append_only BEFORE DELETE OR UPDATE ON public.application_user_events FOR EACH ROW EXECUTE FUNCTION public.reject_application_sync_immutable_mutation();


--
-- Name: applications applications_stable_public_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER applications_stable_public_identity BEFORE UPDATE ON public.applications FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('project_id', 'public_id');


--
-- Name: audit_events audit_events_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_events_append_only BEFORE DELETE OR UPDATE ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.reject_audit_event_mutation();


--
-- Name: control_idempotency_records control_idempotency_identity_mutation_result_authority; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER control_idempotency_identity_mutation_result_authority BEFORE UPDATE OF project_id, request_digest, state, result_resource_id, operation_kind, request_scope, completed_at ON public.control_idempotency_records FOR EACH ROW EXECUTE FUNCTION public.owlauth_reject_identity_mutation_idempotency_authority_change();


--
-- Name: email_challenges email_challenges_exact_mutation_outbox; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER email_challenges_exact_mutation_outbox AFTER INSERT OR DELETE OR UPDATE ON public.email_challenges DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_mutation_email_challenge_outbox();


--
-- Name: email_challenges email_challenges_exact_typed_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER email_challenges_exact_typed_owner AFTER INSERT OR DELETE OR UPDATE ON public.email_challenges DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_email_challenge_typed_owner();


--
-- Name: email_challenges email_challenges_stable_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER email_challenges_stable_owner BEFORE UPDATE ON public.email_challenges FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('project_id', 'application_id', 'owner_kind', 'transaction_id', 'identity_mutation_intent_id', 'identity_mutation_proof_slot_id', 'generation', 'smtp_selection_kind', 'smtp_configuration_id', 'smtp_generation', 'smtp_security_eligibility_revision');


--
-- Name: email_identities email_identities_merge_tombstone_primary_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER email_identities_merge_tombstone_primary_owner AFTER INSERT OR DELETE OR UPDATE OF user_id ON public.email_identities DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_merge_tombstone_primary_final_owner();


--
-- Name: email_identities email_identities_no_merged_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER email_identities_no_merged_owner AFTER INSERT OR DELETE OR UPDATE OF user_id ON public.email_identities DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_merged_project_user_identity_ownership();


--
-- Name: identity_mutation_candidate_evidence identity_mutation_candidate_evidence_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_mutation_candidate_evidence_immutable BEFORE UPDATE ON public.identity_mutation_candidate_evidence FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('id', 'project_id', 'intent_id', 'slot_id', 'identity_kind', 'candidate_revision', 'protector_key_version', 'evidence_ciphertext', 'evidence_digest', 'created_at', 'retain_until');


--
-- Name: identity_mutation_candidate_evidence identity_mutation_candidate_evidence_matches_slot; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_mutation_candidate_evidence_matches_slot AFTER INSERT OR DELETE OR UPDATE ON public.identity_mutation_candidate_evidence DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_candidate_evidence();


--
-- Name: identity_mutation_proof_slots identity_mutation_candidate_slot_matches_evidence; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_mutation_candidate_slot_matches_evidence AFTER UPDATE OF state, identity_kind, slot_role ON public.identity_mutation_proof_slots DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN ((new.slot_role = 'candidate_identity'::text)) EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_candidate_evidence();


--
-- Name: identity_mutation_create_results identity_mutation_create_results_exact_terminal_state; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_mutation_create_results_exact_terminal_state AFTER INSERT OR DELETE OR UPDATE ON public.identity_mutation_create_results DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_create_result_terminal_state();


--
-- Name: identity_mutation_create_results identity_mutation_create_results_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_mutation_create_results_no_delete BEFORE DELETE ON public.identity_mutation_create_results FOR EACH ROW EXECUTE FUNCTION public.owlauth_reject_identity_mutation_create_result_delete();


--
-- Name: identity_mutation_create_results identity_mutation_create_results_one_way_lifecycle; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_mutation_create_results_one_way_lifecycle BEFORE INSERT OR UPDATE ON public.identity_mutation_create_results FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_create_result_lifecycle();


--
-- Name: identity_mutation_create_results identity_mutation_create_results_stable_authority; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_mutation_create_results_stable_authority BEFORE UPDATE ON public.identity_mutation_create_results FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('idempotency_key', 'project_id', 'intent_id', 'request_digest', 'create_result_key_version', 'expires_at');


--
-- Name: identity_mutation_intents identity_mutation_email_intent_reverse_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_mutation_email_intent_reverse_owner AFTER UPDATE ON public.identity_mutation_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_email_challenge_typed_owner();


--
-- Name: identity_mutation_proof_slots identity_mutation_email_slot_reverse_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_mutation_email_slot_reverse_owner AFTER UPDATE ON public.identity_mutation_proof_slots DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_email_challenge_typed_owner();


--
-- Name: identity_mutation_intents identity_mutation_intents_exact_create_result_terminal_state; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_mutation_intents_exact_create_result_terminal_state AFTER INSERT OR UPDATE OF status ON public.identity_mutation_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_create_result_terminal_state();


--
-- Name: identity_mutation_intents identity_mutation_intents_exact_merge_tombstone; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_mutation_intents_exact_merge_tombstone AFTER INSERT OR UPDATE OF operation_kind, status, terminal_at ON public.identity_mutation_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_merge_tombstone();


--
-- Name: identity_mutation_intents identity_mutation_intents_exact_slot_set; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_mutation_intents_exact_slot_set AFTER INSERT OR UPDATE OF operation_kind, status ON public.identity_mutation_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_slot_set();


--
-- Name: identity_mutation_intents identity_mutation_intents_one_way_state; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_mutation_intents_one_way_state BEFORE INSERT OR UPDATE ON public.identity_mutation_intents FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_intent_transition();


--
-- Name: identity_mutation_intents identity_mutation_intents_preserve_create_authority; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_mutation_intents_preserve_create_authority BEFORE DELETE ON public.identity_mutation_intents FOR EACH ROW EXECUTE FUNCTION public.owlauth_reject_identity_mutation_intent_delete_with_result();


--
-- Name: identity_mutation_intents identity_mutation_intents_primary_source_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_mutation_intents_primary_source_owner BEFORE INSERT ON public.identity_mutation_intents FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_identity_mutation_primary_source_owner();


--
-- Name: identity_mutation_intents identity_mutation_intents_stable_authority; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_mutation_intents_stable_authority BEFORE UPDATE ON public.identity_mutation_intents FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('project_id', 'operation_kind', 'project_metadata_revision', 'project_security_revision', 'destination_user_id', 'destination_user_revision', 'destination_user_security_revision', 'identity_owner_user_id', 'identity_owner_user_revision', 'identity_owner_user_security_revision', 'winner_user_id', 'winner_user_revision', 'winner_user_security_revision', 'loser_user_id', 'loser_user_revision', 'loser_user_security_revision', 'primary_source_disposition', 'primary_provider_identity_id', 'primary_email_identity_id', 'primary_source_identity_revision', 'sessions_disposition', 'bindings_disposition', 'hosted_handle_digest', 'hosted_handle_digest_key_version', 'correlation_id', 'created_at', 'expires_at');


--
-- Name: identity_mutation_proof_slots identity_mutation_slots_callback_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_mutation_slots_callback_owner AFTER INSERT OR DELETE OR UPDATE OF provider_configuration_id, provider_started_at ON public.identity_mutation_proof_slots DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_provider_callback_owner();


--
-- Name: identity_mutation_proof_slots identity_mutation_slots_capture_original_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_mutation_slots_capture_original_owner BEFORE INSERT ON public.identity_mutation_proof_slots FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_identity_mutation_slot_original_owner();


--
-- Name: identity_mutation_proof_slots identity_mutation_slots_exact_slot_set; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_mutation_slots_exact_slot_set AFTER INSERT OR DELETE OR UPDATE ON public.identity_mutation_proof_slots DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_slot_set();


--
-- Name: identity_mutation_proof_slots identity_mutation_slots_one_way_state; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_mutation_slots_one_way_state BEFORE INSERT OR UPDATE ON public.identity_mutation_proof_slots FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_slot_transition();


--
-- Name: identity_mutation_proof_slots identity_mutation_slots_stable_authority; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_mutation_slots_stable_authority BEFORE UPDATE ON public.identity_mutation_proof_slots FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('project_id', 'intent_id', 'slot_ordinal', 'slot_role', 'purpose', 'identity_kind', 'proof_user_id', 'expected_user_revision', 'expected_user_security_revision', 'existing_provider_identity_id', 'existing_email_identity_id', 'expected_identity_revision', 'application_id', 'application_security_revision', 'method_kind', 'provider_adapter_key', 'provider_adapter_capability_revision', 'provider_configuration_id', 'provider_revision', 'provider_assignment_security_revision', 'provider_scopes', 'callback_url', 'provider_pkce_required', 'oidc_nonce_required', 'email_assignment_application_id', 'email_policy_revision', 'email_security_revision', 'email_assignment_security_revision', 'created_at');


--
-- Name: identity_proof_receipts identity_proof_receipts_exact_slot_state; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER identity_proof_receipts_exact_slot_state AFTER INSERT OR DELETE OR UPDATE ON public.identity_proof_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_slot_set();


--
-- Name: identity_proof_receipts identity_proof_receipts_match_slot; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_proof_receipts_match_slot BEFORE INSERT OR UPDATE ON public.identity_proof_receipts FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_proof_receipt();


--
-- Name: identity_proof_receipts identity_proof_receipts_one_way_state; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_proof_receipts_one_way_state BEFORE INSERT OR UPDATE ON public.identity_proof_receipts FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_proof_receipt_transition();


--
-- Name: identity_proof_receipts identity_proof_receipts_stable_evidence; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER identity_proof_receipts_stable_evidence BEFORE UPDATE ON public.identity_proof_receipts FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('project_id', 'intent_id', 'slot_id', 'evidence_kind', 'identity_kind', 'provider_identity_id', 'email_identity_id', 'candidate_evidence_id', 'evidence_revision', 'proof_user_id', 'proof_user_revision', 'proof_user_security_revision', 'interaction_browser_binding_digest', 'interaction_browser_binding_digest_key_version', 'interaction_browser_binding_revision', 'captured_intent_revision', 'purpose', 'receipt_digest', 'receipt_digest_key_version', 'issued_at', 'expires_at', 'created_at');


--
-- Name: project_key_rings key_rings_stable_public_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER key_rings_stable_public_identity BEFORE UPDATE ON public.project_key_rings FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('project_id', 'issuer', 'purpose', 'algorithm');


--
-- Name: key_state_events key_state_events_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER key_state_events_append_only BEFORE DELETE OR UPDATE ON public.key_state_events FOR EACH ROW EXECUTE FUNCTION public.reject_audit_event_mutation();


--
-- Name: linked_identities linked_identities_merge_tombstone_primary_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER linked_identities_merge_tombstone_primary_owner AFTER INSERT OR DELETE OR UPDATE OF user_id ON public.linked_identities DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_merge_tombstone_primary_final_owner();


--
-- Name: linked_identities linked_identities_no_merged_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER linked_identities_no_merged_owner AFTER INSERT OR DELETE OR UPDATE OF user_id ON public.linked_identities DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_merged_project_user_identity_ownership();


--
-- Name: login_transaction_methods login_transaction_methods_validate_provider_snapshot; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER login_transaction_methods_validate_provider_snapshot BEFORE INSERT OR UPDATE OF method_kind, provider_kind, provider_egress_policy_revision ON public.login_transaction_methods FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_provider_method_snapshot();


--
-- Name: login_transactions login_transactions_callback_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER login_transactions_callback_owner AFTER INSERT OR DELETE OR UPDATE OF provider_configuration_id, upstream_state_digest ON public.login_transactions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_provider_callback_owner();


--
-- Name: mail_outbox mail_outbox_exact_challenge_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER mail_outbox_exact_challenge_owner AFTER INSERT OR UPDATE OF project_id, transaction_id, challenge_id, challenge_generation ON public.mail_outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_mail_outbox_challenge_owner();


--
-- Name: mail_outbox mail_outbox_reverse_mutation_challenge; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER mail_outbox_reverse_mutation_challenge AFTER INSERT OR DELETE OR UPDATE ON public.mail_outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_mutation_email_challenge_outbox();


--
-- Name: mail_outbox mail_outbox_stable_challenge_authority; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mail_outbox_stable_challenge_authority BEFORE UPDATE ON public.mail_outbox FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('project_id', 'transaction_id', 'challenge_id', 'challenge_generation', 'smtp_selection_kind', 'smtp_configuration_id', 'smtp_generation', 'smtp_security_eligibility_revision', 'created_at');


--
-- Name: managed_provider_connections managed_provider_connection_materialize_fairness; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER managed_provider_connection_materialize_fairness AFTER INSERT ON public.managed_provider_connections FOR EACH ROW EXECUTE FUNCTION public.materialize_managed_provider_claim_fairness();


--
-- Name: managed_provider_reauthorization_interactions managed_reauthorization_bounded_deadline; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER managed_reauthorization_bounded_deadline BEFORE UPDATE OF expires_at ON public.managed_provider_reauthorization_interactions FOR EACH ROW EXECUTE FUNCTION public.owlauth_reject_managed_reauthorization_deadline_extension();


--
-- Name: managed_provider_reauthorization_interactions managed_reauthorization_bounded_revocation_truth; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER managed_reauthorization_bounded_revocation_truth BEFORE UPDATE OF supports_revocation ON public.managed_provider_reauthorization_interactions FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_managed_reauthorization_revocation_truth();


--
-- Name: managed_provider_reauthorization_interactions managed_reauthorization_capture_original_authority; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER managed_reauthorization_capture_original_authority BEFORE INSERT ON public.managed_provider_reauthorization_interactions FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_managed_reauthorization_original_authority();


--
-- Name: managed_provider_reauthorization_interactions managed_reauthorization_expanded_authority; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER managed_reauthorization_expanded_authority BEFORE UPDATE OF provider_kind, provider_egress_policy_revision, secret_material_id, provider_display_name ON public.managed_provider_reauthorization_interactions FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_managed_reauthorization_expanded_authority_upd();


--
-- Name: managed_provider_reauthorization_interactions managed_reauthorization_stable_authority; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER managed_reauthorization_stable_authority BEFORE UPDATE ON public.managed_provider_reauthorization_interactions FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('project_id', 'project_public_id', 'connection_id', 'linked_identity_id', 'user_id', 'provider_configuration_id', 'provider_key', 'issuer', 'subject', 'client_id', 'application_id', 'expected_connection_generation', 'expected_credential_generation', 'expected_connection_revision', 'project_security_revision', 'user_security_revision', 'identity_revision', 'provider_revision', 'managed_profile_revision', 'application_revision', 'assignment_security_revision', 'callback_url', 'adapter_key', 'adapter_capability_revision', 'required_scopes', 'provider_pkce_required', 'oidc_nonce_required', 'created_at');


--
-- Name: managed_provider_reauthorization_interactions managed_reauthorizations_callback_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER managed_reauthorizations_callback_owner AFTER INSERT OR DELETE OR UPDATE OF provider_configuration_id, provider_started_at ON public.managed_provider_reauthorization_interactions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_provider_callback_owner();


--
-- Name: project_server_keys project_server_keys_lifecycle; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER project_server_keys_lifecycle BEFORE INSERT OR UPDATE ON public.project_server_keys FOR EACH ROW EXECUTE FUNCTION public.enforce_project_server_key_lifecycle();


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_capture_primary_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER project_user_merge_tombstones_capture_primary_owner BEFORE INSERT ON public.project_user_merge_tombstones FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_merge_tombstone_primary_original_owner();


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_exact_intent; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_exact_intent AFTER INSERT OR UPDATE ON public.project_user_merge_tombstones DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_project_user_merge_tombstone();


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_final_primary_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_final_primary_owner AFTER INSERT OR DELETE OR UPDATE ON public.project_user_merge_tombstones DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_merge_tombstone_primary_final_owner();


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER project_user_merge_tombstones_immutable BEFORE DELETE OR UPDATE ON public.project_user_merge_tombstones FOR EACH ROW EXECUTE FUNCTION public.owlauth_reject_project_user_merge_tombstone_mutation();


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_reverse_attribution; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_reverse_attribution AFTER INSERT OR DELETE OR UPDATE ON public.project_user_merge_tombstones DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_merged_project_user_attribution();


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_reverse_exact_intent; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER project_user_merge_tombstones_reverse_exact_intent AFTER INSERT OR DELETE OR UPDATE ON public.project_user_merge_tombstones DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_identity_mutation_merge_tombstone();


--
-- Name: project_users project_users_exact_merged_attribution; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER project_users_exact_merged_attribution AFTER INSERT OR UPDATE OF status, merged_into_user_id ON public.project_users DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_merged_project_user_attribution();


--
-- Name: project_users project_users_exact_primary_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER project_users_exact_primary_identity AFTER INSERT OR UPDATE OF status, primary_source_kind, primary_profile_identity_id, primary_email_identity_id, merged_into_user_id ON public.project_users DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_exact_primary_identity();


--
-- Name: project_users project_users_merged_terminal_state; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER project_users_merged_terminal_state BEFORE UPDATE ON public.project_users FOR EACH ROW EXECUTE FUNCTION public.owlauth_reject_merged_project_user_change();


--
-- Name: project_users project_users_no_live_binding_after_merge; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER project_users_no_live_binding_after_merge AFTER INSERT OR UPDATE OF status, merged_into_user_id ON public.project_users DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_merged_user_binding_ownership();


--
-- Name: projects projects_initialize_email_policy; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER projects_initialize_email_policy AFTER INSERT ON public.projects FOR EACH ROW EXECUTE FUNCTION public.owlauth_initialize_project_email_policy();


--
-- Name: projects projects_initialize_provider_egress_policy; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER projects_initialize_provider_egress_policy AFTER INSERT ON public.projects FOR EACH ROW EXECUTE FUNCTION public.owlauth_initialize_project_provider_egress_policy();


--
-- Name: projects projects_stable_public_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER projects_stable_public_identity BEFORE UPDATE ON public.projects FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('public_id');


--
-- Name: protected_materials protected_material_identity_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER protected_material_identity_immutable BEFORE UPDATE ON public.protected_materials FOR EACH ROW EXECUTE FUNCTION public.owlauth_protected_material_identity_immutable();


--
-- Name: protected_materials protected_material_inventory_revision_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER protected_material_inventory_revision_trigger AFTER INSERT OR DELETE OR UPDATE ON public.protected_materials FOR EACH STATEMENT EXECUTE FUNCTION public.owlauth_bump_material_inventory_revision();


--
-- Name: protected_materials protected_material_owner_integrity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER protected_material_owner_integrity AFTER INSERT OR UPDATE OF project_id, owner_kind, owner_id, generation, state ON public.protected_materials DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_validate_protected_material_owner();


--
-- Name: provider_callback_owners provider_callback_owners_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER provider_callback_owners_immutable BEFORE UPDATE ON public.provider_callback_owners FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('state_id', 'project_id', 'provider_configuration_id', 'owner_kind', 'login_transaction_id', 'identity_mutation_intent_id', 'identity_mutation_proof_slot_id', 'managed_reauthorization_interaction_id', 'created_at');


--
-- Name: provider_callback_owners provider_callback_owners_reverse_presence; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER provider_callback_owners_reverse_presence AFTER INSERT OR DELETE OR UPDATE ON public.provider_callback_owners DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.owlauth_enforce_provider_callback_owner();


--
-- Name: provider_configurations providers_stable_callback_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER providers_stable_callback_identity BEFORE UPDATE ON public.provider_configurations FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('project_id', 'provider_key', 'kind', 'issuer', 'client_id', 'callback_url');


--
-- Name: application_publishable_keys publishable_keys_stable_public_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER publishable_keys_stable_public_identity BEFORE UPDATE ON public.application_publishable_keys FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('project_id', 'application_id', 'public_id');


--
-- Name: project_signing_keys signing_keys_public_jwk_write_once; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER signing_keys_public_jwk_write_once BEFORE UPDATE ON public.project_signing_keys FOR EACH ROW EXECUTE FUNCTION public.reject_published_jwk_change();


--
-- Name: project_signing_keys signing_keys_stable_public_identity; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER signing_keys_stable_public_identity BEFORE UPDATE ON public.project_signing_keys FOR EACH ROW EXECUTE FUNCTION public.reject_immutable_column_change('project_id', 'ring_id', 'kid', 'signer_material_id');


--
-- Name: webhook_delivery_attempts webhook_delivery_attempts_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER webhook_delivery_attempts_append_only BEFORE DELETE OR UPDATE ON public.webhook_delivery_attempts FOR EACH ROW EXECUTE FUNCTION public.reject_webhook_attempt_immutable_mutation();


--
-- Name: webhook_endpoints webhook_endpoint_immutable_target; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER webhook_endpoint_immutable_target BEFORE UPDATE ON public.webhook_endpoints FOR EACH ROW EXECUTE FUNCTION public.enforce_webhook_endpoint_immutable_target();


--
-- Name: webhook_secret_generations webhook_secret_immutable_material; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER webhook_secret_immutable_material BEFORE UPDATE ON public.webhook_secret_generations FOR EACH ROW EXECUTE FUNCTION public.enforce_webhook_secret_immutable_material();


--
-- Name: application_email_assignments application_email_assignments_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_email_assignments
    ADD CONSTRAINT application_email_assignments_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id) ON DELETE CASCADE;


--
-- Name: application_origins application_origins_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_origins
    ADD CONSTRAINT application_origins_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id) ON DELETE CASCADE;


--
-- Name: application_provider_assignments application_provider_assignments_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_provider_assignments
    ADD CONSTRAINT application_provider_assignments_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id) ON DELETE CASCADE;


--
-- Name: application_provider_assignments application_provider_assignments_project_id_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_provider_assignments
    ADD CONSTRAINT application_provider_assignments_project_id_provider_id_fkey FOREIGN KEY (project_id, provider_id) REFERENCES public.provider_configurations(project_id, id) ON DELETE CASCADE;


--
-- Name: application_publishable_keys application_publishable_keys_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_publishable_keys
    ADD CONSTRAINT application_publishable_keys_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id) ON DELETE CASCADE;


--
-- Name: application_redirects application_redirects_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_redirects
    ADD CONSTRAINT application_redirects_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id) ON DELETE CASCADE;


--
-- Name: application_sessions application_sessions_binding_identity_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_sessions
    ADD CONSTRAINT application_sessions_binding_identity_fk FOREIGN KEY (project_id, binding_id, application_id) REFERENCES public.application_user_bindings(project_id, id, application_id);


--
-- Name: application_sessions application_sessions_credential_user_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_sessions
    ADD CONSTRAINT application_sessions_credential_user_fk FOREIGN KEY (project_id, user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: application_sessions application_sessions_project_id_browser_session_id_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_sessions
    ADD CONSTRAINT application_sessions_project_id_browser_session_id_user_id_fkey FOREIGN KEY (project_id, browser_session_id, user_id) REFERENCES public.project_browser_sessions(project_id, id, user_id);


--
-- Name: application_user_bindings application_user_bindings_merged_into_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_bindings
    ADD CONSTRAINT application_user_bindings_merged_into_fk FOREIGN KEY (project_id, merged_into_binding_id, application_id) REFERENCES public.application_user_bindings(project_id, id, application_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: application_user_bindings application_user_bindings_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_bindings
    ADD CONSTRAINT application_user_bindings_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id) ON DELETE CASCADE;


--
-- Name: application_user_bindings application_user_bindings_project_id_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_bindings
    ADD CONSTRAINT application_user_bindings_project_id_user_id_fkey FOREIGN KEY (project_id, user_id) REFERENCES public.project_users(project_id, id) ON DELETE CASCADE;


--
-- Name: application_user_events application_user_event_application_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_events
    ADD CONSTRAINT application_user_event_application_fk FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id);


--
-- Name: application_user_events application_user_event_binding_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_events
    ADD CONSTRAINT application_user_event_binding_fk FOREIGN KEY (project_id, binding_id, application_id) REFERENCES public.application_user_bindings(project_id, id, application_id);


--
-- Name: application_user_events application_user_event_historical_user_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_events
    ADD CONSTRAINT application_user_event_historical_user_fk FOREIGN KEY (project_id, user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: application_user_projections application_user_projections_binding_owner_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_projections
    ADD CONSTRAINT application_user_projections_binding_owner_fk FOREIGN KEY (project_id, binding_id, application_id, user_id) REFERENCES public.application_user_bindings(project_id, id, application_id, user_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: application_user_projections application_user_projections_verified_email_source_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_user_projections
    ADD CONSTRAINT application_user_projections_verified_email_source_fk FOREIGN KEY (project_id, verified_email_source_identity_id, user_id) REFERENCES public.email_identities(project_id, id, user_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: applications applications_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: audit_events audit_events_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: control_idempotency_records control_idempotency_records_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.control_idempotency_records
    ADD CONSTRAINT control_idempotency_records_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: deployment_smtp_generations deployment_smtp_generations_credential_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_smtp_generations
    ADD CONSTRAINT deployment_smtp_generations_credential_material_id_fkey FOREIGN KEY (credential_material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: deployment_smtp_secret_operations deployment_smtp_secret_operations_generation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_smtp_secret_operations
    ADD CONSTRAINT deployment_smtp_secret_operations_generation_fkey FOREIGN KEY (generation) REFERENCES public.deployment_smtp_generations(generation) ON DELETE RESTRICT;


--
-- Name: deployment_smtp_secret_operations deployment_smtp_secret_operations_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_smtp_secret_operations
    ADD CONSTRAINT deployment_smtp_secret_operations_material_id_fkey FOREIGN KEY (material_id) REFERENCES public.protected_materials(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;


--
-- Name: email_challenges email_challenges_mutation_slot_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_challenges
    ADD CONSTRAINT email_challenges_mutation_slot_fk FOREIGN KEY (project_id, identity_mutation_intent_id, identity_mutation_proof_slot_id) REFERENCES public.identity_mutation_proof_slots(project_id, intent_id, id) ON DELETE CASCADE;


--
-- Name: email_challenges email_challenges_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_challenges
    ADD CONSTRAINT email_challenges_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id);


--
-- Name: email_challenges email_challenges_project_id_smtp_configuration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_challenges
    ADD CONSTRAINT email_challenges_project_id_smtp_configuration_id_fkey FOREIGN KEY (project_id, smtp_configuration_id) REFERENCES public.project_smtp_configurations(project_id, id);


--
-- Name: email_challenges email_challenges_project_id_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_challenges
    ADD CONSTRAINT email_challenges_project_id_transaction_id_fkey FOREIGN KEY (project_id, transaction_id) REFERENCES public.login_transactions(project_id, id) ON DELETE CASCADE;


--
-- Name: email_identities email_identities_project_id_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_identities
    ADD CONSTRAINT email_identities_project_id_user_id_fkey FOREIGN KEY (project_id, user_id) REFERENCES public.project_users(project_id, id) ON DELETE CASCADE;


--
-- Name: email_identity_aliases email_identity_aliases_project_id_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_identity_aliases
    ADD CONSTRAINT email_identity_aliases_project_id_identity_id_fkey FOREIGN KEY (project_id, identity_id) REFERENCES public.email_identities(project_id, id) ON DELETE CASCADE;


--
-- Name: handoff_tickets handoff_tickets_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.handoff_tickets
    ADD CONSTRAINT handoff_tickets_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id);


--
-- Name: handoff_tickets handoff_tickets_project_id_browser_session_id_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.handoff_tickets
    ADD CONSTRAINT handoff_tickets_project_id_browser_session_id_user_id_fkey FOREIGN KEY (project_id, browser_session_id, user_id) REFERENCES public.project_browser_sessions(project_id, id, user_id);


--
-- Name: handoff_tickets handoff_tickets_project_id_login_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.handoff_tickets
    ADD CONSTRAINT handoff_tickets_project_id_login_transaction_id_fkey FOREIGN KEY (project_id, login_transaction_id) REFERENCES public.login_transactions(project_id, id) ON DELETE CASCADE;


--
-- Name: handoff_tickets handoff_tickets_project_id_provider_configuration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.handoff_tickets
    ADD CONSTRAINT handoff_tickets_project_id_provider_configuration_id_fkey FOREIGN KEY (project_id, provider_configuration_id) REFERENCES public.provider_configurations(project_id, id);


--
-- Name: handoff_tickets handoff_tickets_project_id_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.handoff_tickets
    ADD CONSTRAINT handoff_tickets_project_id_user_id_fkey FOREIGN KEY (project_id, user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: identity_mutation_candidate_evidence identity_mutation_candidate_e_project_id_intent_id_slot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_candidate_evidence
    ADD CONSTRAINT identity_mutation_candidate_e_project_id_intent_id_slot_id_fkey FOREIGN KEY (project_id, intent_id, slot_id) REFERENCES public.identity_mutation_proof_slots(project_id, intent_id, id) ON DELETE CASCADE;


--
-- Name: identity_mutation_create_results identity_mutation_create_results_idempotency_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_create_results
    ADD CONSTRAINT identity_mutation_create_results_idempotency_key_fkey FOREIGN KEY (idempotency_key) REFERENCES public.control_idempotency_records(idempotency_key);


--
-- Name: identity_mutation_create_results identity_mutation_create_results_project_id_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_create_results
    ADD CONSTRAINT identity_mutation_create_results_project_id_intent_id_fkey FOREIGN KEY (project_id, intent_id) REFERENCES public.identity_mutation_intents(project_id, id) ON DELETE CASCADE;


--
-- Name: identity_mutation_intents identity_mutation_intents_project_id_destination_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_intents
    ADD CONSTRAINT identity_mutation_intents_project_id_destination_user_id_fkey FOREIGN KEY (project_id, destination_user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: identity_mutation_intents identity_mutation_intents_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_intents
    ADD CONSTRAINT identity_mutation_intents_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: identity_mutation_intents identity_mutation_intents_project_id_identity_owner_user_i_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_intents
    ADD CONSTRAINT identity_mutation_intents_project_id_identity_owner_user_i_fkey FOREIGN KEY (project_id, identity_owner_user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: identity_mutation_intents identity_mutation_intents_project_id_loser_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_intents
    ADD CONSTRAINT identity_mutation_intents_project_id_loser_user_id_fkey FOREIGN KEY (project_id, loser_user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: identity_mutation_intents identity_mutation_intents_project_id_primary_email_identit_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_intents
    ADD CONSTRAINT identity_mutation_intents_project_id_primary_email_identit_fkey FOREIGN KEY (project_id, primary_email_identity_id) REFERENCES public.email_identities(project_id, id);


--
-- Name: identity_mutation_intents identity_mutation_intents_project_id_primary_provider_iden_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_intents
    ADD CONSTRAINT identity_mutation_intents_project_id_primary_provider_iden_fkey FOREIGN KEY (project_id, primary_provider_identity_id) REFERENCES public.linked_identities(project_id, id);


--
-- Name: identity_mutation_intents identity_mutation_intents_project_id_winner_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_intents
    ADD CONSTRAINT identity_mutation_intents_project_id_winner_user_id_fkey FOREIGN KEY (project_id, winner_user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_application_id_pr_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_application_id_pr_fkey FOREIGN KEY (project_id, application_id, provider_configuration_id) REFERENCES public.application_provider_assignments(project_id, application_id, provider_id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_email_assignment__fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_email_assignment__fkey FOREIGN KEY (project_id, email_assignment_application_id) REFERENCES public.application_email_assignments(project_id, application_id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_existing_email_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_existing_email_id_fkey FOREIGN KEY (project_id, existing_email_identity_id) REFERENCES public.email_identities(project_id, id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_existing_provider_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_existing_provider_fkey FOREIGN KEY (project_id, existing_provider_identity_id) REFERENCES public.linked_identities(project_id, id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_intent_id_fkey FOREIGN KEY (project_id, intent_id) REFERENCES public.identity_mutation_intents(project_id, id) ON DELETE CASCADE;


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_proof_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_proof_user_id_fkey FOREIGN KEY (project_id, proof_user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_project_id_provider_configur_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_project_id_provider_configur_fkey FOREIGN KEY (project_id, provider_configuration_id) REFERENCES public.provider_configurations(project_id, id);


--
-- Name: identity_mutation_proof_slots identity_mutation_proof_slots_provider_secret_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_mutation_proof_slots
    ADD CONSTRAINT identity_mutation_proof_slots_provider_secret_material_id_fkey FOREIGN KEY (provider_secret_material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: identity_proof_receipts identity_proof_receipts_project_id_email_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_proof_receipts
    ADD CONSTRAINT identity_proof_receipts_project_id_email_identity_id_fkey FOREIGN KEY (project_id, email_identity_id) REFERENCES public.email_identities(project_id, id);


--
-- Name: identity_proof_receipts identity_proof_receipts_project_id_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_proof_receipts
    ADD CONSTRAINT identity_proof_receipts_project_id_intent_id_fkey FOREIGN KEY (project_id, intent_id) REFERENCES public.identity_mutation_intents(project_id, id) ON DELETE CASCADE;


--
-- Name: identity_proof_receipts identity_proof_receipts_project_id_intent_id_slot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_proof_receipts
    ADD CONSTRAINT identity_proof_receipts_project_id_intent_id_slot_id_fkey FOREIGN KEY (project_id, intent_id, slot_id) REFERENCES public.identity_mutation_proof_slots(project_id, intent_id, id) ON DELETE CASCADE;


--
-- Name: identity_proof_receipts identity_proof_receipts_project_id_proof_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_proof_receipts
    ADD CONSTRAINT identity_proof_receipts_project_id_proof_user_id_fkey FOREIGN KEY (project_id, proof_user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: identity_proof_receipts identity_proof_receipts_project_id_provider_identity_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_proof_receipts
    ADD CONSTRAINT identity_proof_receipts_project_id_provider_identity_id_fkey FOREIGN KEY (project_id, provider_identity_id) REFERENCES public.linked_identities(project_id, id);


--
-- Name: key_provisioning_operations key_provisioning_operations_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_provisioning_operations
    ADD CONSTRAINT key_provisioning_operations_material_id_fkey FOREIGN KEY (material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: key_provisioning_operations key_provisioning_operations_project_id_ring_id_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_provisioning_operations
    ADD CONSTRAINT key_provisioning_operations_project_id_ring_id_key_id_fkey FOREIGN KEY (project_id, ring_id, key_id) REFERENCES public.project_signing_keys(project_id, ring_id, id) ON DELETE CASCADE;


--
-- Name: key_state_events key_state_events_project_id_ring_id_signing_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_state_events
    ADD CONSTRAINT key_state_events_project_id_ring_id_signing_key_id_fkey FOREIGN KEY (project_id, ring_id, signing_key_id) REFERENCES public.project_signing_keys(project_id, ring_id, id);


--
-- Name: linked_identities linked_identities_project_id_created_via_provider_configur_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.linked_identities
    ADD CONSTRAINT linked_identities_project_id_created_via_provider_configur_fkey FOREIGN KEY (project_id, created_via_provider_configuration_id) REFERENCES public.provider_configurations(project_id, id);


--
-- Name: linked_identities linked_identities_project_id_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.linked_identities
    ADD CONSTRAINT linked_identities_project_id_user_id_fkey FOREIGN KEY (project_id, user_id) REFERENCES public.project_users(project_id, id) ON DELETE CASCADE;


--
-- Name: login_email_method_snapshots login_email_method_snapshots_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_email_method_snapshots
    ADD CONSTRAINT login_email_method_snapshots_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id);


--
-- Name: login_email_method_snapshots login_email_method_snapshots_project_id_smtp_configuration_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_email_method_snapshots
    ADD CONSTRAINT login_email_method_snapshots_project_id_smtp_configuration_fkey FOREIGN KEY (project_id, smtp_configuration_id) REFERENCES public.project_smtp_configurations(project_id, id);


--
-- Name: login_email_method_snapshots login_email_method_snapshots_project_id_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_email_method_snapshots
    ADD CONSTRAINT login_email_method_snapshots_project_id_transaction_id_fkey FOREIGN KEY (project_id, transaction_id) REFERENCES public.login_transactions(project_id, id) ON DELETE CASCADE;


--
-- Name: login_transaction_methods login_transaction_methods_project_id_provider_configuratio_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_transaction_methods
    ADD CONSTRAINT login_transaction_methods_project_id_provider_configuratio_fkey FOREIGN KEY (project_id, provider_configuration_id) REFERENCES public.provider_configurations(project_id, id);


--
-- Name: login_transaction_methods login_transaction_methods_project_id_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_transaction_methods
    ADD CONSTRAINT login_transaction_methods_project_id_transaction_id_fkey FOREIGN KEY (project_id, transaction_id) REFERENCES public.login_transactions(project_id, id) ON DELETE CASCADE;


--
-- Name: login_transactions login_transactions_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_transactions
    ADD CONSTRAINT login_transactions_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id) ON DELETE CASCADE;


--
-- Name: login_transactions login_transactions_project_id_provider_configuration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_transactions
    ADD CONSTRAINT login_transactions_project_id_provider_configuration_id_fkey FOREIGN KEY (project_id, provider_configuration_id) REFERENCES public.provider_configurations(project_id, id);


--
-- Name: login_transactions login_transactions_project_id_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_transactions
    ADD CONSTRAINT login_transactions_project_id_user_id_fkey FOREIGN KEY (project_id, user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: magic_transfer_contexts magic_transfer_contexts_challenge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.magic_transfer_contexts
    ADD CONSTRAINT magic_transfer_contexts_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES public.email_challenges(id) ON DELETE CASCADE;


--
-- Name: mail_outbox mail_outbox_exact_challenge_generation_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_outbox
    ADD CONSTRAINT mail_outbox_exact_challenge_generation_fk FOREIGN KEY (project_id, challenge_id, challenge_generation) REFERENCES public.email_challenges(project_id, id, generation) ON DELETE CASCADE;


--
-- Name: mail_outbox mail_outbox_project_id_challenge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_outbox
    ADD CONSTRAINT mail_outbox_project_id_challenge_id_fkey FOREIGN KEY (project_id, challenge_id) REFERENCES public.email_challenges(project_id, id) ON DELETE CASCADE;


--
-- Name: mail_outbox mail_outbox_project_id_smtp_configuration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_outbox
    ADD CONSTRAINT mail_outbox_project_id_smtp_configuration_id_fkey FOREIGN KEY (project_id, smtp_configuration_id) REFERENCES public.project_smtp_configurations(project_id, id);


--
-- Name: mail_outbox mail_outbox_project_id_transaction_id_challenge_generation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mail_outbox
    ADD CONSTRAINT mail_outbox_project_id_transaction_id_challenge_generation_fkey FOREIGN KEY (project_id, transaction_id, challenge_generation) REFERENCES public.email_challenges(project_id, transaction_id, generation) ON DELETE CASCADE;


--
-- Name: managed_provider_claim_fairness managed_provider_claim_fairne_project_id_provider_configur_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_claim_fairness
    ADD CONSTRAINT managed_provider_claim_fairne_project_id_provider_configur_fkey FOREIGN KEY (project_id, provider_configuration_id) REFERENCES public.provider_configurations(project_id, id) ON DELETE CASCADE;


--
-- Name: managed_provider_connections managed_provider_connections_identity_owner_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_connections
    ADD CONSTRAINT managed_provider_connections_identity_owner_fk FOREIGN KEY (project_id, linked_identity_id, user_id) REFERENCES public.linked_identities(project_id, id, user_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;


--
-- Name: managed_provider_connections managed_provider_connections_project_id_provider_configura_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_connections
    ADD CONSTRAINT managed_provider_connections_project_id_provider_configura_fkey FOREIGN KEY (project_id, provider_configuration_id) REFERENCES public.provider_configurations(project_id, id);


--
-- Name: managed_provider_credentials managed_provider_credentials_project_id_connection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_credentials
    ADD CONSTRAINT managed_provider_credentials_project_id_connection_id_fkey FOREIGN KEY (project_id, connection_id) REFERENCES public.managed_provider_connections(project_id, id) ON DELETE CASCADE;


--
-- Name: managed_provider_reauthorization_interactions managed_provider_reauthorizat_project_id_application_id_pr_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_provider_reauthorizat_project_id_application_id_pr_fkey FOREIGN KEY (project_id, application_id, provider_configuration_id) REFERENCES public.application_provider_assignments(project_id, application_id, provider_id);


--
-- Name: managed_provider_reauthorization_interactions managed_provider_reauthorizat_project_id_provider_configur_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_provider_reauthorizat_project_id_provider_configur_fkey FOREIGN KEY (project_id, provider_configuration_id) REFERENCES public.provider_configurations(project_id, id);


--
-- Name: managed_provider_reauthorization_interactions managed_provider_reauthorization__project_id_connection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_provider_reauthorization__project_id_connection_id_fkey FOREIGN KEY (project_id, connection_id) REFERENCES public.managed_provider_connections(project_id, id) ON DELETE CASCADE;


--
-- Name: managed_provider_reauthorization_interactions managed_provider_reauthorization_identity_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_provider_reauthorization_identity_fk FOREIGN KEY (project_id, linked_identity_id) REFERENCES public.linked_identities(project_id, id) ON DELETE CASCADE;


--
-- Name: managed_provider_reauthorization_interactions managed_provider_reauthorization_interactions_secret_material_i; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_provider_reauthorization_interactions_secret_material_i FOREIGN KEY (secret_material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: managed_provider_reauthorization_interactions managed_provider_reauthorization_project_id_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_reauthorization_interactions
    ADD CONSTRAINT managed_provider_reauthorization_project_id_application_id_fkey FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id);


--
-- Name: managed_provider_renewal_operations managed_provider_renewal_operatio_project_id_connection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_provider_renewal_operations
    ADD CONSTRAINT managed_provider_renewal_operatio_project_id_connection_id_fkey FOREIGN KEY (project_id, connection_id) REFERENCES public.managed_provider_connections(project_id, id) ON DELETE CASCADE;


--
-- Name: managed_reauthorization_create_results managed_reauthorization_create_r_project_id_interaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_reauthorization_create_results
    ADD CONSTRAINT managed_reauthorization_create_r_project_id_interaction_id_fkey FOREIGN KEY (project_id, interaction_id) REFERENCES public.managed_provider_reauthorization_interactions(project_id, id) ON DELETE CASCADE;


--
-- Name: managed_reauthorization_create_results managed_reauthorization_create_results_idempotency_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_reauthorization_create_results
    ADD CONSTRAINT managed_reauthorization_create_results_idempotency_key_fkey FOREIGN KEY (idempotency_key) REFERENCES public.control_idempotency_records(idempotency_key);


--
-- Name: project_browser_logout_interactions project_browser_logout_intera_project_id_application_sessi_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_browser_logout_interactions
    ADD CONSTRAINT project_browser_logout_intera_project_id_application_sessi_fkey FOREIGN KEY (project_id, application_session_id, application_id, user_id) REFERENCES public.application_sessions(project_id, id, application_id, user_id);


--
-- Name: project_browser_logout_interactions project_browser_logout_intera_project_id_browser_session_i_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_browser_logout_interactions
    ADD CONSTRAINT project_browser_logout_intera_project_id_browser_session_i_fkey FOREIGN KEY (project_id, browser_session_id, user_id) REFERENCES public.project_browser_sessions(project_id, id, user_id);


--
-- Name: project_browser_sessions project_browser_sessions_project_id_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_browser_sessions
    ADD CONSTRAINT project_browser_sessions_project_id_user_id_fkey FOREIGN KEY (project_id, user_id) REFERENCES public.project_users(project_id, id) ON DELETE CASCADE;


--
-- Name: project_server_keys project_server_keys_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_server_keys
    ADD CONSTRAINT project_server_keys_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE RESTRICT;


--
-- Name: project_email_policies project_email_policies_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_email_policies
    ADD CONSTRAINT project_email_policies_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_key_rings project_key_rings_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_key_rings
    ADD CONSTRAINT project_key_rings_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_policies project_policies_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_policies
    ADD CONSTRAINT project_policies_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_provider_egress_policies project_provider_egress_policies_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_provider_egress_policies
    ADD CONSTRAINT project_provider_egress_policies_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_signing_keys project_signing_keys_project_id_ring_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_signing_keys
    ADD CONSTRAINT project_signing_keys_project_id_ring_id_fkey FOREIGN KEY (project_id, ring_id) REFERENCES public.project_key_rings(project_id, id) ON DELETE CASCADE;


--
-- Name: project_signing_keys project_signing_keys_signer_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_signing_keys
    ADD CONSTRAINT project_signing_keys_signer_material_id_fkey FOREIGN KEY (signer_material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: project_smtp_configurations project_smtp_configurations_credential_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_configurations
    ADD CONSTRAINT project_smtp_configurations_credential_material_id_fkey FOREIGN KEY (credential_material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: project_smtp_configurations project_smtp_configurations_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_configurations
    ADD CONSTRAINT project_smtp_configurations_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_smtp_runtime_readiness project_smtp_runtime_readiness_project_id_configuration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_runtime_readiness
    ADD CONSTRAINT project_smtp_runtime_readiness_project_id_configuration_id_fkey FOREIGN KEY (project_id, configuration_id) REFERENCES public.project_smtp_configurations(project_id, id) ON DELETE CASCADE;


--
-- Name: project_smtp_secret_operations project_smtp_secret_material_owner_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_secret_operations
    ADD CONSTRAINT project_smtp_secret_material_owner_fk FOREIGN KEY (project_id, configuration_id, material_id) REFERENCES public.project_smtp_configurations(project_id, id, credential_material_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: project_smtp_secret_operations project_smtp_secret_operations_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_secret_operations
    ADD CONSTRAINT project_smtp_secret_operations_material_id_fkey FOREIGN KEY (material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: project_smtp_secret_operations project_smtp_secret_operations_project_id_configuration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_secret_operations
    ADD CONSTRAINT project_smtp_secret_operations_project_id_configuration_id_fkey FOREIGN KEY (project_id, configuration_id) REFERENCES public.project_smtp_configurations(project_id, id) ON DELETE CASCADE;


--
-- Name: project_smtp_secret_operations project_smtp_secret_operations_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_secret_operations
    ADD CONSTRAINT project_smtp_secret_operations_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_smtp_test_operations project_smtp_test_credential_owner_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_test_operations
    ADD CONSTRAINT project_smtp_test_credential_owner_fk FOREIGN KEY (project_id, configuration_id, configuration_generation, credential_material_id) REFERENCES public.project_smtp_configurations(project_id, id, generation, credential_material_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: project_smtp_test_operations project_smtp_test_operations_credential_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_test_operations
    ADD CONSTRAINT project_smtp_test_operations_credential_material_id_fkey FOREIGN KEY (credential_material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: project_smtp_test_operations project_smtp_test_operations_project_id_configuration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_test_operations
    ADD CONSTRAINT project_smtp_test_operations_project_id_configuration_id_fkey FOREIGN KEY (project_id, configuration_id) REFERENCES public.project_smtp_configurations(project_id, id) ON DELETE CASCADE;


--
-- Name: project_smtp_test_operations project_smtp_test_operations_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_test_operations
    ADD CONSTRAINT project_smtp_test_operations_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: project_smtp_test_operations project_smtp_test_operations_recipient_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_smtp_test_operations
    ADD CONSTRAINT project_smtp_test_operations_recipient_material_id_fkey FOREIGN KEY (recipient_material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_intent_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_user_merge_tombstones
    ADD CONSTRAINT project_user_merge_tombstones_intent_fk FOREIGN KEY (project_id, identity_mutation_intent_id) REFERENCES public.identity_mutation_intents(project_id, id);


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_primary_email_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_user_merge_tombstones
    ADD CONSTRAINT project_user_merge_tombstones_primary_email_fk FOREIGN KEY (project_id, primary_email_identity_id) REFERENCES public.email_identities(project_id, id);


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_primary_provider_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_user_merge_tombstones
    ADD CONSTRAINT project_user_merge_tombstones_primary_provider_fk FOREIGN KEY (project_id, primary_provider_identity_id) REFERENCES public.linked_identities(project_id, id);


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_project_id_loser_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_user_merge_tombstones
    ADD CONSTRAINT project_user_merge_tombstones_project_id_loser_user_id_fkey FOREIGN KEY (project_id, loser_user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: project_user_merge_tombstones project_user_merge_tombstones_project_id_winner_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_user_merge_tombstones
    ADD CONSTRAINT project_user_merge_tombstones_project_id_winner_user_id_fkey FOREIGN KEY (project_id, winner_user_id) REFERENCES public.project_users(project_id, id);


--
-- Name: project_users project_users_merged_into_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_users
    ADD CONSTRAINT project_users_merged_into_fk FOREIGN KEY (project_id, merged_into_user_id) REFERENCES public.project_users(project_id, id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: project_users project_users_primary_email_identity_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_users
    ADD CONSTRAINT project_users_primary_email_identity_fk FOREIGN KEY (project_id, primary_email_identity_id, id) REFERENCES public.email_identities(project_id, id, user_id);


--
-- Name: project_users project_users_primary_profile_identity_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_users
    ADD CONSTRAINT project_users_primary_profile_identity_fk FOREIGN KEY (project_id, primary_profile_identity_id, id) REFERENCES public.linked_identities(project_id, id, user_id);


--
-- Name: project_users project_users_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_users
    ADD CONSTRAINT project_users_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: protected_materials protected_materials_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protected_materials
    ADD CONSTRAINT protected_materials_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE RESTRICT;


--
-- Name: provider_callback_owners provider_callback_owners_project_id_identity_mutation_inte_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_callback_owners
    ADD CONSTRAINT provider_callback_owners_project_id_identity_mutation_inte_fkey FOREIGN KEY (project_id, identity_mutation_intent_id, identity_mutation_proof_slot_id) REFERENCES public.identity_mutation_proof_slots(project_id, intent_id, id) ON DELETE CASCADE;


--
-- Name: provider_callback_owners provider_callback_owners_project_id_login_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_callback_owners
    ADD CONSTRAINT provider_callback_owners_project_id_login_transaction_id_fkey FOREIGN KEY (project_id, login_transaction_id) REFERENCES public.login_transactions(project_id, id) ON DELETE CASCADE;


--
-- Name: provider_callback_owners provider_callback_owners_project_id_managed_reauthorizatio_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_callback_owners
    ADD CONSTRAINT provider_callback_owners_project_id_managed_reauthorizatio_fkey FOREIGN KEY (project_id, managed_reauthorization_interaction_id) REFERENCES public.managed_provider_reauthorization_interactions(project_id, id) ON DELETE CASCADE;


--
-- Name: provider_callback_owners provider_callback_owners_project_id_provider_configuration_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_callback_owners
    ADD CONSTRAINT provider_callback_owners_project_id_provider_configuration_fkey FOREIGN KEY (project_id, provider_configuration_id) REFERENCES public.provider_configurations(project_id, id);


--
-- Name: provider_configurations provider_configurations_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_configurations
    ADD CONSTRAINT provider_configurations_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: provider_configurations provider_configurations_secret_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_configurations
    ADD CONSTRAINT provider_configurations_secret_material_id_fkey FOREIGN KEY (secret_material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: provider_secret_operations provider_secret_operations_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_secret_operations
    ADD CONSTRAINT provider_secret_operations_material_id_fkey FOREIGN KEY (material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: provider_secret_operations provider_secret_operations_project_id_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_secret_operations
    ADD CONSTRAINT provider_secret_operations_project_id_provider_id_fkey FOREIGN KEY (project_id, provider_id) REFERENCES public.provider_configurations(project_id, id) ON DELETE CASCADE;


--
-- Name: refresh_families refresh_families_project_id_application_session_id_applica_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_families
    ADD CONSTRAINT refresh_families_project_id_application_session_id_applica_fkey FOREIGN KEY (project_id, application_session_id, application_id, user_id) REFERENCES public.application_sessions(project_id, id, application_id, user_id) ON DELETE CASCADE;


--
-- Name: refresh_token_generations refresh_token_generations_project_id_family_id_application_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_token_generations
    ADD CONSTRAINT refresh_token_generations_project_id_family_id_application_fkey FOREIGN KEY (project_id, family_id, application_id, user_id) REFERENCES public.refresh_families(project_id, id, application_id, user_id) ON DELETE CASCADE;


--
-- Name: runtime_publication_leases runtime_publication_leases_project_id_ring_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runtime_publication_leases
    ADD CONSTRAINT runtime_publication_leases_project_id_ring_id_fkey FOREIGN KEY (project_id, ring_id) REFERENCES public.project_key_rings(project_id, id) ON DELETE CASCADE;


--
-- Name: smtp_credential_cleanup_operations smtp_credential_cleanup_operations_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smtp_credential_cleanup_operations
    ADD CONSTRAINT smtp_credential_cleanup_operations_material_id_fkey FOREIGN KEY (material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: smtp_credential_cleanup_operations smtp_credential_cleanup_operations_project_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smtp_credential_cleanup_operations
    ADD CONSTRAINT smtp_credential_cleanup_operations_project_id_fkey FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: webhook_deliveries webhook_deliveries_claimed_overlap_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_claimed_overlap_material_id_fkey FOREIGN KEY (claimed_overlap_material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webhook_deliveries webhook_deliveries_claimed_secret_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_claimed_secret_material_id_fkey FOREIGN KEY (claimed_secret_material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webhook_deliveries webhook_deliveries_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_endpoint_id_fkey FOREIGN KEY (endpoint_id) REFERENCES public.webhook_endpoints(id);


--
-- Name: webhook_deliveries webhook_deliveries_replay_of_delivery_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_replay_of_delivery_id_fkey FOREIGN KEY (replay_of_delivery_id) REFERENCES public.webhook_deliveries(id);


--
-- Name: webhook_delivery_attempts webhook_delivery_attempts_delivery_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_delivery_attempts
    ADD CONSTRAINT webhook_delivery_attempts_delivery_id_fkey FOREIGN KEY (delivery_id) REFERENCES public.webhook_deliveries(id);


--
-- Name: webhook_deliveries webhook_delivery_claimed_overlap_material_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_delivery_claimed_overlap_material_fk FOREIGN KEY (endpoint_id, claimed_overlap_generation, claimed_overlap_material_id) REFERENCES public.webhook_secret_generations(endpoint_id, generation, material_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webhook_deliveries webhook_delivery_claimed_secret_material_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_delivery_claimed_secret_material_fk FOREIGN KEY (endpoint_id, claimed_secret_generation, claimed_secret_material_id) REFERENCES public.webhook_secret_generations(endpoint_id, generation, material_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webhook_deliveries webhook_delivery_dispatch_state_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_delivery_dispatch_state_fk FOREIGN KEY (project_id, application_id) REFERENCES public.webhook_application_dispatch_state(project_id, application_id);


--
-- Name: webhook_deliveries webhook_delivery_event_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_delivery_event_fk FOREIGN KEY (project_id, application_id, event_id) REFERENCES public.application_user_events(project_id, application_id, id);


--
-- Name: webhook_deliveries webhook_delivery_replay_parent_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_delivery_replay_parent_fk FOREIGN KEY (project_id, application_id, endpoint_id, event_id, replay_of_delivery_id) REFERENCES public.webhook_deliveries(project_id, application_id, endpoint_id, event_id, id);


--
-- Name: webhook_deliveries webhook_delivery_scope_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_delivery_scope_fk FOREIGN KEY (project_id, application_id, endpoint_id) REFERENCES public.webhook_endpoints(project_id, application_id, id);


--
-- Name: webhook_application_dispatch_state webhook_dispatch_application_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_application_dispatch_state
    ADD CONSTRAINT webhook_dispatch_application_fk FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id);


--
-- Name: webhook_endpoints webhook_endpoint_application_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoint_application_fk FOREIGN KEY (project_id, application_id) REFERENCES public.applications(project_id, id);


--
-- Name: webhook_endpoints webhook_endpoint_current_secret_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoint_current_secret_fk FOREIGN KEY (id, current_secret_generation) REFERENCES public.webhook_secret_generations(endpoint_id, generation) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webhook_endpoints webhook_endpoint_overlap_secret_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoint_overlap_secret_fk FOREIGN KEY (id, overlap_secret_generation) REFERENCES public.webhook_secret_generations(endpoint_id, generation) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webhook_secret_cleanup_operations webhook_secret_cleanup_generation_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_secret_cleanup_operations
    ADD CONSTRAINT webhook_secret_cleanup_generation_fk FOREIGN KEY (endpoint_id, generation) REFERENCES public.webhook_secret_generations(endpoint_id, generation);


--
-- Name: webhook_secret_cleanup_operations webhook_secret_cleanup_material_generation_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_secret_cleanup_operations
    ADD CONSTRAINT webhook_secret_cleanup_material_generation_fk FOREIGN KEY (endpoint_id, generation, material_id) REFERENCES public.webhook_secret_generations(endpoint_id, generation, material_id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webhook_secret_cleanup_operations webhook_secret_cleanup_operations_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_secret_cleanup_operations
    ADD CONSTRAINT webhook_secret_cleanup_operations_material_id_fkey FOREIGN KEY (material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: webhook_secret_generations webhook_secret_generations_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_secret_generations
    ADD CONSTRAINT webhook_secret_generations_endpoint_id_fkey FOREIGN KEY (endpoint_id) REFERENCES public.webhook_endpoints(id);


--
-- Name: webhook_secret_generations webhook_secret_generations_material_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_secret_generations
    ADD CONSTRAINT webhook_secret_generations_material_id_fkey FOREIGN KEY (material_id) REFERENCES public.protected_materials(id) DEFERRABLE INITIALLY DEFERRED;
