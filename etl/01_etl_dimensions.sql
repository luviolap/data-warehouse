-- Network Security Data Mart - Dimension ETL
-- Version: 1.1
-- For UNSW-NB15 Dataset

-- Initialize ETL Control
CREATE OR REPLACE PROCEDURE init_etl_batch(
    p_source_system VARCHAR(50),
    OUT p_batch_id BIGINT
) LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO ETL_CONTROL (
        start_time,
        status,
        source_system,
        aggregation_level
    ) VALUES (
        CURRENT_TIMESTAMP,
        'STARTED',
        p_source_system,
        'RAW'
    ) RETURNING batch_id INTO p_batch_id;
END;
$$;

-- Time Dimension Population
CREATE OR REPLACE PROCEDURE populate_time_dimension(
    p_batch_id BIGINT,
    p_start_date TIMESTAMP,
    p_end_date TIMESTAMP
) LANGUAGE plpgsql AS $$
DECLARE
    v_current_date TIMESTAMP;
BEGIN
    -- Create sequence if it doesn't exist
    DROP SEQUENCE IF EXISTS time_id_seq;
    CREATE SEQUENCE time_id_seq START WITH 1;

    v_current_date := p_start_date;
    
    WHILE v_current_date <= p_end_date LOOP
        INSERT INTO DIM_TIME (
            time_id,
            datetime,
            hour,
            day,
            month,
            year,
            day_type,
            day_name,
            month_name,
            is_business_hour,
            is_peak_hour,
            week_of_year,
            quarter,
            batch_id
        ) VALUES (
            nextval('time_id_seq'),
            v_current_date,
            EXTRACT(HOUR FROM v_current_date),
            EXTRACT(DAY FROM v_current_date),
            EXTRACT(MONTH FROM v_current_date),
            EXTRACT(YEAR FROM v_current_date),
            CASE 
                WHEN EXTRACT(DOW FROM v_current_date) IN (0, 6) THEN 'WEEKEND'
                ELSE 'WEEKDAY'
            END,
            TO_CHAR(v_current_date, 'Day'),
            TO_CHAR(v_current_date, 'Month'),
            CASE 
                WHEN EXTRACT(HOUR FROM v_current_date) BETWEEN 9 AND 17 
                AND EXTRACT(DOW FROM v_current_date) NOT IN (0, 6) THEN TRUE
                ELSE FALSE
            END,
            CASE 
                WHEN EXTRACT(HOUR FROM v_current_date) IN (9, 10, 11, 14, 15, 16) THEN TRUE
                ELSE FALSE
            END,
            EXTRACT(WEEK FROM v_current_date),
            EXTRACT(QUARTER FROM v_current_date),
            p_batch_id
        ) ON CONFLICT (datetime) DO NOTHING;
        
        v_current_date := v_current_date + INTERVAL '1 hour';
    END LOOP;
END;
$$;

-- Service Dimension Population
CREATE OR REPLACE PROCEDURE populate_service_dimension(
    p_batch_id BIGINT
) LANGUAGE plpgsql AS $$
BEGIN
    -- Create sequence if it doesn't exist
    DROP SEQUENCE IF EXISTS service_id_seq;
    CREATE SEQUENCE service_id_seq START WITH 1;

    -- Insert default service if not exists
    INSERT INTO DIM_SERVICE (
        service_id,
        name,
        protocol,
        service_type,
        category,
        risk_level,
        description,
        batch_id
    ) VALUES (
        0,
        'UNKNOWN',
        'UNKNOWN',
        'UNKNOWN',
        'UNKNOWN',
        'LOW',
        'Default service for unknown values',
        p_batch_id
    ) ON CONFLICT (name, valid_from, version) DO NOTHING;

    -- Insert services from source data
    INSERT INTO DIM_SERVICE (
        service_id,
        name,
        protocol,
        service_type,
        category,
        risk_level,
        description,
        batch_id
    )
    SELECT DISTINCT
        nextval('service_id_seq'),
        COALESCE(service, 'UNKNOWN'),
        proto,
        'NETWORK',  -- Default service_type
        CASE 
            WHEN service IN ('http', 'ftp', 'smtp') THEN 'WEB'
            WHEN service IN ('dns') THEN 'NAME_SERVICE'
            WHEN service IN ('ssh') THEN 'REMOTE_ACCESS'
            ELSE 'OTHER'
        END,
        CASE 
            WHEN service IN ('ssh', 'ftp') THEN 'HIGH'
            WHEN service IN ('http', 'smtp') THEN 'MEDIUM'
            ELSE 'LOW'
        END,
        'Service extracted from UNSW-NB15 dataset',
        p_batch_id
    FROM staging.source_data
    WHERE service IS NOT NULL
    ON CONFLICT (name, valid_from, version) DO NOTHING;
END;
$$;

-- Protocol Dimension Population
CREATE OR REPLACE PROCEDURE populate_protocol_dimension(
    p_batch_id BIGINT
) LANGUAGE plpgsql AS $$
BEGIN
    -- Create sequence if it doesn't exist
    DROP SEQUENCE IF EXISTS protocol_id_seq;
    CREATE SEQUENCE protocol_id_seq START WITH 1;

    -- Insert default protocol
    INSERT INTO DIM_PROTOCOL (
        protocol_id,
        name,
        type,
        description,
        batch_id
    ) VALUES (
        0,
        'UNKNOWN',
        'UNKNOWN',
        'Default protocol for unknown values',
        p_batch_id
    ) ON CONFLICT (name) DO NOTHING;

    -- Insert protocols from source data
    INSERT INTO DIM_PROTOCOL (
        protocol_id,
        name,
        type,
        description,
        batch_id
    )
    SELECT DISTINCT
        nextval('protocol_id_seq'),
        proto,
        CASE 
            WHEN proto IN ('tcp', 'udp') THEN 'TRANSPORT'
            WHEN proto = 'icmp' THEN 'INTERNET'
            ELSE 'OTHER'
        END,
        'Protocol extracted from UNSW-NB15 dataset',
        p_batch_id
    FROM staging.source_data
    WHERE proto IS NOT NULL
    ON CONFLICT (name) DO NOTHING;
END;
$$;

-- State Dimension Population
CREATE OR REPLACE PROCEDURE populate_state_dimension(
    p_batch_id BIGINT
) LANGUAGE plpgsql AS $$
BEGIN
    -- Create sequence if it doesn't exist
    DROP SEQUENCE IF EXISTS state_id_seq;
    CREATE SEQUENCE state_id_seq START WITH 1;

    -- Insert default state
    INSERT INTO DIM_STATE (
        state_id,
        name,
        category,
        description,
        batch_id
    ) VALUES (
        0,
        'UNKNOWN',
        'UNKNOWN',
        'Default state for unknown values',
        p_batch_id
    ) ON CONFLICT (name) DO NOTHING;

    -- Insert states from source data
    INSERT INTO DIM_STATE (
        state_id,
        name,
        category,
        description,
        batch_id
    )
    SELECT DISTINCT
        nextval('state_id_seq'),
        state,
        CASE 
            WHEN state IN ('CON', 'INT') THEN 'CONNECTION'
            WHEN state IN ('ACC', 'CLO') THEN 'ACCESS'
            ELSE 'OTHER'
        END,
        'Connection state from UNSW-NB15 dataset',
        p_batch_id
    FROM staging.source_data
    WHERE state IS NOT NULL
    ON CONFLICT (name) DO NOTHING;
END;
$$;

-- Port Dimension Population
CREATE OR REPLACE PROCEDURE populate_port_dimension(
    p_batch_id BIGINT
) LANGUAGE plpgsql AS $$
BEGIN
    -- Create sequence if it doesn't exist
    DROP SEQUENCE IF EXISTS port_id_seq;
    CREATE SEQUENCE port_id_seq START WITH 1;

    -- Insert default port
    INSERT INTO DIM_PORT (
        port_id,
        port_number,
        range_type,
        default_service,
        is_active,
        valid_from,
        version,
        batch_id
    ) VALUES (
        0,
        0,
        'UNKNOWN',
        'UNKNOWN',
        TRUE,
        CURRENT_TIMESTAMP,
        1,
        p_batch_id
    ) ON CONFLICT (port_number, valid_from, version) DO NOTHING;
    
    RAISE NOTICE 'Default port inserted successfully';

    -- Insert source ports
    INSERT INTO DIM_PORT (
        port_id,
        port_number,
        range_type,
        default_service,
        is_active,
        valid_from,
        version,
        batch_id
    )
    SELECT DISTINCT
        nextval('port_id_seq'),
        sport,
        CASE 
            WHEN sport < 1024 THEN 'SYSTEM'
            WHEN sport < 49152 THEN 'USER'
            ELSE 'DYNAMIC'
        END,
        COALESCE(service, 'UNKNOWN'),
        TRUE,
        CURRENT_TIMESTAMP,
        1,
        p_batch_id
    FROM staging.source_data
    WHERE sport IS NOT NULL
    ON CONFLICT (port_number, valid_from, version) DO NOTHING;
    
    RAISE NOTICE 'Source ports inserted successfully';

    -- Insert destination ports
    INSERT INTO DIM_PORT (
        port_id,
        port_number,
        range_type,
        default_service,
        is_active,
        valid_from,
        version,
        batch_id
    )
    SELECT DISTINCT
        nextval('port_id_seq'),
        dsport,
        CASE 
            WHEN dsport < 1024 THEN 'SYSTEM'
            WHEN dsport < 49152 THEN 'USER'
            ELSE 'DYNAMIC'
        END,
        COALESCE(service, 'UNKNOWN'),
        TRUE,
        CURRENT_TIMESTAMP,
        1,
        p_batch_id
    FROM staging.source_data
    WHERE dsport IS NOT NULL
    ON CONFLICT (port_number, valid_from, version) DO NOTHING;
    
    RAISE NOTICE 'Destination ports inserted successfully';
END;
$$;

-- Attack Dimension Population
CREATE OR REPLACE PROCEDURE populate_attack_dimension(
    p_batch_id BIGINT
) LANGUAGE plpgsql AS $$
BEGIN
    -- Create sequence if it doesn't exist
    DROP SEQUENCE IF EXISTS attack_id_seq;
    CREATE SEQUENCE attack_id_seq START WITH 1;

    -- Insert default attack category (normal traffic)
    INSERT INTO DIM_ATTACK (
        attack_id,
        category,
        is_attack,
        severity,
        description,
        is_active,
        batch_id
    ) VALUES (
        0,
        'NORMAL',
        FALSE,
        1,
        'Normal traffic, no attack detected',
        TRUE,
        p_batch_id
    ) ON CONFLICT (category) DO NOTHING;

    -- Insert attack categories from source data
    INSERT INTO DIM_ATTACK (
        attack_id,
        category,
        is_attack,
        severity,
        description,
        is_active,
        batch_id
    )
    SELECT DISTINCT
        nextval('attack_id_seq'),
        COALESCE(attack_cat, 'NORMAL'),
        CASE WHEN attack_cat IS NOT NULL AND attack_cat != '' THEN TRUE ELSE FALSE END,
        CASE 
            WHEN attack_cat IN ('Backdoors', 'Shellcode', 'Worms') THEN 5
            WHEN attack_cat IN ('DoS', 'Exploits') THEN 4
            WHEN attack_cat IN ('Fuzzers', 'Generic') THEN 3
            WHEN attack_cat IN ('Analysis', 'Reconnaissance') THEN 2
            ELSE 1
        END,
        'Attack category from UNSW-NB15 dataset',
        TRUE,
        p_batch_id
    FROM staging.source_data
    WHERE attack_cat IS NOT NULL AND attack_cat != ''
    ON CONFLICT (category) DO NOTHING;
    
    RAISE NOTICE 'Attack categories populated successfully';
END;
$$;

-- Main ETL Procedure for Dimensions
CREATE OR REPLACE PROCEDURE etl_load_dimensions(
    p_source_system VARCHAR(50),
    p_start_date TIMESTAMP,
    p_end_date TIMESTAMP
) LANGUAGE plpgsql AS $$
DECLARE
    v_batch_id BIGINT;
    v_error_message TEXT;
BEGIN
    -- Initialize ETL batch
    CALL init_etl_batch(p_source_system, v_batch_id);
    
    BEGIN
        -- Load dimensions
        CALL populate_time_dimension(v_batch_id, p_start_date, p_end_date);
        CALL populate_service_dimension(v_batch_id);
        CALL populate_protocol_dimension(v_batch_id);
        CALL populate_state_dimension(v_batch_id);
        CALL populate_port_dimension(v_batch_id);
        CALL populate_attack_dimension(v_batch_id);

        -- Update ETL control status
        UPDATE ETL_CONTROL 
        SET status = 'COMPLETED',
            end_time = CURRENT_TIMESTAMP
        WHERE batch_id = v_batch_id;
        
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_error_message = MESSAGE_TEXT;
        
        UPDATE ETL_CONTROL 
        SET status = 'FAILED',
            end_time = CURRENT_TIMESTAMP,
            error_message = v_error_message
        WHERE batch_id = v_batch_id;
        
        RAISE EXCEPTION 'ETL Dimension Load Failed: %', v_error_message;
    END;
END;
$$;

-- Alter the check constraint to include 'UNKNOWN'
ALTER TABLE DIM_PORT DROP CONSTRAINT IF EXISTS dim_port_range_type_check;
ALTER TABLE DIM_PORT ADD CONSTRAINT dim_port_range_type_check 
    CHECK (range_type IN ('SYSTEM', 'USER', 'DYNAMIC', 'UNKNOWN'));

-- Execute the dimension loading process
CALL etl_load_dimensions(
    'UNSW-NB15',                    -- source system name
    '2024-01-01 00:00:00'::timestamp,  -- start date
    '2024-12-31 23:59:59'::timestamp   -- end date
);

-- Check counts and sample data from each dimension
SELECT 'DIM_TIME' as dimension, COUNT(*) as record_count FROM DIM_TIME
UNION ALL
SELECT 'DIM_SERVICE', COUNT(*) FROM DIM_SERVICE WHERE is_active = true
UNION ALL
SELECT 'DIM_PROTOCOL', COUNT(*) FROM DIM_PROTOCOL WHERE is_active = true
UNION ALL
SELECT 'DIM_STATE', COUNT(*) FROM DIM_STATE WHERE is_active = true
UNION ALL
SELECT 'DIM_PORT', COUNT(*) FROM DIM_PORT WHERE is_active = true
UNION ALL
SELECT 'DIM_ATTACK', COUNT(*) FROM DIM_ATTACK WHERE is_active = true;

-- Check ETL_CONTROL status
SELECT batch_id, start_time, end_time, status, error_message 
FROM ETL_CONTROL 
ORDER BY batch_id DESC 
LIMIT 1;