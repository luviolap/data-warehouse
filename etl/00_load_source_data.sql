-- Network Security Data Mart - Source Data Loading
-- Version: 1.0
-- For UNSW-NB15 Dataset

-- Create staging schema
CREATE SCHEMA IF NOT EXISTS staging;

-- Drop existing staging tables if they exist
DROP TABLE IF EXISTS staging.source_data;
DROP TABLE IF EXISTS staging.features_metadata;

-- Create features metadata table
CREATE TABLE staging.features_metadata (
    feature_id INTEGER PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    data_type VARCHAR(50) NOT NULL,
    description TEXT,
    CONSTRAINT uk_feature_name UNIQUE (name)
);

-- Create source data staging table with proper data types based on features.csv
CREATE TABLE staging.source_data (
    srcip VARCHAR(50),
    sport INTEGER,
    dstip VARCHAR(50),
    dsport INTEGER,
    proto VARCHAR(10),
    state VARCHAR(10),
    dur FLOAT,
    sbytes INTEGER,
    dbytes INTEGER,
    sttl INTEGER,
    dttl INTEGER,
    sloss INTEGER,
    dloss INTEGER,
    service VARCHAR(50),
    sload FLOAT,
    dload FLOAT,
    spkts INTEGER,
    dpkts INTEGER,
    swin INTEGER,
    dwin INTEGER,
    stcpb INTEGER,
    dtcpb INTEGER,
    smeansz INTEGER,
    dmeansz INTEGER,
    trans_depth INTEGER,
    res_bdy_len INTEGER,
    sjit FLOAT,
    djit FLOAT,
    stime BIGINT,
    ltime BIGINT,
    sintpkt FLOAT,
    dintpkt FLOAT,
    tcprtt FLOAT,
    synack FLOAT,
    ackdat FLOAT,
    is_sm_ips_ports BOOLEAN,
    ct_state_ttl INTEGER,
    ct_flw_http_mthd INTEGER,
    is_ftp_login BOOLEAN,
    ct_ftp_cmd INTEGER,
    ct_srv_src INTEGER,
    ct_srv_dst INTEGER,
    ct_dst_ltm INTEGER,
    ct_src_ltm INTEGER,
    ct_src_dport_ltm INTEGER,
    ct_dst_sport_ltm INTEGER,
    ct_dst_src_ltm INTEGER,
    attack_cat VARCHAR(50),
    label INTEGER,
    
    -- Add validation check constraints
    CONSTRAINT chk_port_range_src CHECK (sport BETWEEN 0 AND 65535),
    CONSTRAINT chk_port_range_dst CHECK (dsport BETWEEN 0 AND 65535),
    CONSTRAINT chk_duration CHECK (dur >= 0),
    CONSTRAINT chk_bytes CHECK (sbytes >= 0 AND dbytes >= 0),
    CONSTRAINT chk_packets CHECK (spkts >= 0 AND dpkts >= 0),
    CONSTRAINT chk_time CHECK (stime >= 0 AND ltime >= 0 AND ltime >= stime)
);

-- Create error logging table
CREATE TABLE staging.load_errors (
    error_id BIGSERIAL PRIMARY KEY,
    file_name VARCHAR(255),
    line_number INTEGER,
    error_message TEXT,
    raw_data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create function to convert UNIX timestamp to timestamp
CREATE OR REPLACE FUNCTION staging.unix_to_timestamp(unix_time BIGINT)
RETURNS TIMESTAMP AS $$
BEGIN
    RETURN to_timestamp(unix_time);
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create procedure to load features metadata
CREATE OR REPLACE PROCEDURE staging.load_features_metadata(p_file_path TEXT)
LANGUAGE plpgsql AS $$
BEGIN
    -- Load features metadata using COPY command
    EXECUTE format('COPY staging.features_metadata(feature_id, name, data_type, description) 
                   FROM %L WITH (FORMAT CSV, HEADER true)', p_file_path);
                   
    -- Validate required features exist
    IF NOT EXISTS (
        SELECT 1 FROM staging.features_metadata 
        WHERE name IN ('srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'service', 'attack_cat', 'label')
    ) THEN
        RAISE EXCEPTION 'Missing required features in metadata';
    END IF;
END;
$$;

-- Create procedure to load source data
CREATE OR REPLACE PROCEDURE staging.load_source_data(p_file_path TEXT)
LANGUAGE plpgsql AS $$
DECLARE
    v_error_count INTEGER := 0;
    v_success_count INTEGER := 0;
BEGIN
    -- Create temporary table for raw data
    CREATE TEMPORARY TABLE temp_raw_data (
        line_number SERIAL,
        raw_line TEXT
    );
    
    -- Load raw data first
    EXECUTE format('COPY temp_raw_data (raw_line) FROM %L', p_file_path);
    
    -- Insert data with validation
    INSERT INTO staging.source_data
    SELECT 
        split_part(raw_line, ',', 1),                          -- srcip
        NULLIF(split_part(raw_line, ',', 2), '')::INTEGER,    -- sport
        split_part(raw_line, ',', 3),                          -- dstip
        NULLIF(split_part(raw_line, ',', 4), '')::INTEGER,    -- dsport
        split_part(raw_line, ',', 5),                          -- proto
        split_part(raw_line, ',', 6),                          -- state
        NULLIF(split_part(raw_line, ',', 7), '')::FLOAT,      -- dur
        NULLIF(split_part(raw_line, ',', 8), '')::INTEGER,    -- sbytes
        NULLIF(split_part(raw_line, ',', 9), '')::INTEGER,    -- dbytes
        NULLIF(split_part(raw_line, ',', 10), '')::INTEGER,   -- sttl
        NULLIF(split_part(raw_line, ',', 11), '')::INTEGER,   -- dttl
        NULLIF(split_part(raw_line, ',', 12), '')::INTEGER,   -- sloss
        NULLIF(split_part(raw_line, ',', 13), '')::INTEGER,   -- dloss
        NULLIF(split_part(raw_line, ',', 14), ''),            -- service
        NULLIF(split_part(raw_line, ',', 15), '')::FLOAT,     -- sload
        NULLIF(split_part(raw_line, ',', 16), '')::FLOAT,     -- dload
        NULLIF(split_part(raw_line, ',', 17), '')::INTEGER,   -- spkts
        NULLIF(split_part(raw_line, ',', 18), '')::INTEGER,   -- dpkts
        NULLIF(split_part(raw_line, ',', 19), '')::INTEGER,   -- swin
        NULLIF(split_part(raw_line, ',', 20), '')::INTEGER,   -- dwin
        NULLIF(split_part(raw_line, ',', 21), '')::INTEGER,   -- stcpb
        NULLIF(split_part(raw_line, ',', 22), '')::INTEGER,   -- dtcpb
        NULLIF(split_part(raw_line, ',', 23), '')::INTEGER,   -- smeansz
        NULLIF(split_part(raw_line, ',', 24), '')::INTEGER,   -- dmeansz
        NULLIF(split_part(raw_line, ',', 25), '')::INTEGER,   -- trans_depth
        NULLIF(split_part(raw_line, ',', 26), '')::INTEGER,   -- res_bdy_len
        NULLIF(split_part(raw_line, ',', 27), '')::FLOAT,     -- sjit
        NULLIF(split_part(raw_line, ',', 28), '')::FLOAT,     -- djit
        NULLIF(split_part(raw_line, ',', 29), '')::BIGINT,    -- stime
        NULLIF(split_part(raw_line, ',', 30), '')::BIGINT,    -- ltime
        NULLIF(split_part(raw_line, ',', 31), '')::FLOAT,     -- sintpkt
        NULLIF(split_part(raw_line, ',', 32), '')::FLOAT,     -- dintpkt
        NULLIF(split_part(raw_line, ',', 33), '')::FLOAT,     -- tcprtt
        NULLIF(split_part(raw_line, ',', 34), '')::FLOAT,     -- synack
        NULLIF(split_part(raw_line, ',', 35), '')::FLOAT,     -- ackdat
        NULLIF(split_part(raw_line, ',', 36), '')::BOOLEAN,   -- is_sm_ips_ports
        NULLIF(split_part(raw_line, ',', 37), '')::INTEGER,   -- ct_state_ttl
        NULLIF(split_part(raw_line, ',', 38), '')::INTEGER,   -- ct_flw_http_mthd
        NULLIF(split_part(raw_line, ',', 39), '')::BOOLEAN,   -- is_ftp_login
        NULLIF(split_part(raw_line, ',', 40), '')::INTEGER,   -- ct_ftp_cmd
        NULLIF(split_part(raw_line, ',', 41), '')::INTEGER,   -- ct_srv_src
        NULLIF(split_part(raw_line, ',', 42), '')::INTEGER,   -- ct_srv_dst
        NULLIF(split_part(raw_line, ',', 43), '')::INTEGER,   -- ct_dst_ltm
        NULLIF(split_part(raw_line, ',', 44), '')::INTEGER,   -- ct_src_ltm
        NULLIF(split_part(raw_line, ',', 45), '')::INTEGER,   -- ct_src_dport_ltm
        NULLIF(split_part(raw_line, ',', 46), '')::INTEGER,   -- ct_dst_sport_ltm
        NULLIF(split_part(raw_line, ',', 47), '')::INTEGER,   -- ct_dst_src_ltm
        NULLIF(split_part(raw_line, ',', 48), ''),            -- attack_cat
        NULLIF(split_part(raw_line, ',', 49), '')::INTEGER    -- label
    FROM temp_raw_data
    WHERE raw_line !~ '^\s*$'  -- Skip empty lines
    ON CONFLICT DO NOTHING;

    -- Get counts
    GET DIAGNOSTICS v_success_count = ROW_COUNT;
    
    -- Log summary
    RAISE NOTICE 'Loaded % records successfully', v_success_count;
    
    -- Cleanup
    DROP TABLE temp_raw_data;
END;
$$;

-- Create view for data quality checks
CREATE OR REPLACE VIEW staging.data_quality_check AS
SELECT
    COUNT(*) as total_records,
    COUNT(*) FILTER (WHERE srcip IS NULL OR dstip IS NULL) as missing_ips,
    COUNT(*) FILTER (WHERE sport IS NULL OR dsport IS NULL) as missing_ports,
    COUNT(*) FILTER (WHERE proto IS NULL) as missing_protocols,
    COUNT(*) FILTER (WHERE state IS NULL) as missing_states,
    COUNT(*) FILTER (WHERE dur < 0) as negative_durations,
    COUNT(*) FILTER (WHERE sbytes < 0 OR dbytes < 0) as negative_bytes,
    COUNT(*) FILTER (WHERE spkts < 0 OR dpkts < 0) as negative_packets,
    COUNT(*) FILTER (WHERE stime > ltime) as invalid_timestamps,
    COUNT(DISTINCT service) as distinct_services,
    COUNT(DISTINCT attack_cat) as distinct_attack_categories,
    COUNT(*) FILTER (WHERE label NOT IN (0,1)) as invalid_labels
FROM staging.source_data;

-- Main procedure to orchestrate data loading
CREATE OR REPLACE PROCEDURE staging.load_all_data(
    p_features_file TEXT,
    p_data_file TEXT
)
LANGUAGE plpgsql AS $$
BEGIN
    -- Load features metadata
    CALL staging.load_features_metadata(p_features_file);
    
    -- Load source data
    CALL staging.load_source_data(p_data_file);
    
    -- Perform data quality check
    RAISE NOTICE 'Data Quality Summary:';
    RAISE NOTICE '%', (SELECT * FROM staging.data_quality_check);
END;
$$;

-- First load the features metadata
CALL staging.load_features_metadata('/Users/drkp4/Desktop/_itba/warehouse/data-warehouse/data/UNSW-NB15_features.csv');

-- Then load the actual data
CALL staging.load_source_data('/Users/drkp4/Desktop/_itba/warehouse/data-warehouse/data/UNSW-NB15_head.csv');

-- Check the count of records in staging tables
SELECT 'Features Metadata' as table_name, COUNT(*) as record_count 
FROM staging.features_metadata
UNION ALL
SELECT 'Source Data', COUNT(*) 
FROM staging.source_data;

-- Quick look at data quality
SELECT * FROM staging.data_quality_check;