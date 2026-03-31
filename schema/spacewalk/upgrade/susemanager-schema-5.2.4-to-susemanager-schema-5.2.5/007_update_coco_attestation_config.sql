
ALTER TABLE suseServerCoCoAttestationConfig
ADD COLUMN status character varying(32) COLLATE pg_catalog."default" NOT NULL;

ALTER TABLE suseServerCoCoAttestationConfig
ADD COLUMN in_data jsonb NOT NULL;

ALTER TABLE suseServerCoCoAttestationConfig
ADD COLUMN out_data jsonb NOT NULL;

ALTER TABLE suseServerCoCoAttestationConfig
ADD CONSTRAINT suse_srvcocoatt_conf_st_ck CHECK (status::text = ANY (ARRAY['PENDING'::character varying, 'SUCCEEDED'::character varying, 'FAILED'::character varying]::text[]))
