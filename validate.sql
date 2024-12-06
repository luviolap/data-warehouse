-- Network Security Data Mart - Structure Validation Script
-- Version: 1.0

-- Create helper function for formatting output
CREATE OR REPLACE FUNCTION format_validation_header(section_name text) 
RETURNS void AS $$
BEGIN
    RAISE NOTICE '================================================';
    RAISE NOTICE '=== % ===', section_name;
    RAISE NOTICE '================================================';
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    -- 1. Database Tables Check
    PERFORM format_validation_header('DATABASE TABLES CHECK');
    
    WITH table_counts AS (
        SELECT 
            CASE 
                WHEN table_name LIKE 'dim_%' THEN 'Dimension Tables'
                WHEN table_name LIKE 'fact_%' THEN 'Fact Tables'
                WHEN table_name LIKE 'mv_%' THEN 'Materialized Views'
                ELSE 'Other Tables'
            END AS table_type,
            COUNT(*) as count
        FROM information_schema.tables 
        WHERE table_schema = 'public'
        AND table_type = 'BASE TABLE'
        GROUP BY 
            CASE 
                WHEN table_name LIKE 'dim_%' THEN 'Dimension Tables'
                WHEN table_name LIKE 'fact_%' THEN 'Fact Tables'
                WHEN table_name LIKE 'mv_%' THEN 'Materialized Views'
                ELSE 'Other Tables'
            END
    )
    SELECT format('Found %s: %s', table_type, count)
    FROM table_counts;

    -- 2. Detailed Table Structure
    PERFORM format_validation_header('DETAILED TABLE STRUCTURE');
    
    WITH table_details AS (
        SELECT 
            table_name,
            COUNT(*) as column_count,
            STRING_AGG(column_name, ', ') as columns
        FROM information_schema.columns
        WHERE table_schema = 'public'
        AND table_name NOT LIKE 'pg_%'
        GROUP BY table_name
    )
    SELECT format('Table %s has %s columns: %s', 
                 table_name, column_count, columns)
    FROM table_details
    ORDER BY table_name;

    -- 3. Index Check
    PERFORM format_validation_header('INDEX CHECK');
    
    WITH index_counts AS (
        SELECT 
            tablename,
            COUNT(*) as index_count
        FROM pg_indexes
        WHERE schemaname = 'public'
        GROUP BY tablename
    )
    SELECT format('Table %s has %s indexes', 
                 tablename, index_count)
    FROM index_counts
    ORDER BY tablename;

    -- 4. Foreign Key Check
    PERFORM format_validation_header('FOREIGN KEY CHECK');
    
    WITH fk_counts AS (
        SELECT 
            tc.table_name,
            COUNT(*) as fk_count
        FROM information_schema.table_constraints tc
        WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_schema = 'public'
        GROUP BY tc.table_name
    )
    SELECT format('Table %s has %s foreign keys', 
                 table_name, fk_count)
    FROM fk_counts
    ORDER BY table_name;

    -- 5. Materialized Views Check
    PERFORM format_validation_header('MATERIALIZED VIEWS CHECK');
    
    SELECT format('Materialized View: %s (Populated: %s)', 
                 matviewname, ispopulated)
    FROM pg_matviews
    WHERE schemaname = 'public';

    -- 6. Primary Key Check
    PERFORM format_validation_header('PRIMARY KEY CHECK');
    
    WITH pk_info AS (
        SELECT 
            tc.table_name,
            STRING_AGG(kcu.column_name, ', ') as pk_columns
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu 
             ON tc.constraint_name = kcu.constraint_name
        WHERE tc.constraint_type = 'PRIMARY KEY'
        AND tc.table_schema = 'public'
        GROUP BY tc.table_name
    )
    SELECT format('Table %s primary key: %s', 
                 table_name, pk_columns)
    FROM pk_info
    ORDER BY table_name;

    -- 7. Detailed Index Information
    PERFORM format_validation_header('DETAILED INDEX INFORMATION');
    
    SELECT format('Index %s on %s: %s', 
                 indexname, tablename, indexdef)
    FROM pg_indexes
    WHERE schemaname = 'public'
    ORDER BY tablename, indexname;

    -- 8. Dimension Table Record Counts
    PERFORM format_validation_header('DIMENSION TABLE COUNTS');
    
    EXECUTE '
    SELECT format(''DIM_TIME: %s records'', COUNT(*)) FROM DIM_TIME;
    SELECT format(''DIM_SERVICE: %s records'', COUNT(*)) FROM DIM_SERVICE WHERE is_active = true;
    SELECT format(''DIM_ATTACK: %s records'', COUNT(*)) FROM DIM_ATTACK WHERE is_active = true;
    SELECT format(''DIM_PROTOCOL: %s records'', COUNT(*)) FROM DIM_PROTOCOL WHERE is_active = true;
    SELECT format(''DIM_PORT: %s records'', COUNT(*)) FROM DIM_PORT WHERE is_active = true;
    SELECT format(''DIM_STATE: %s records'', COUNT(*)) FROM DIM_STATE WHERE is_active = true;
    ';

    -- 9. ETL Control Check
    PERFORM format_validation_header('ETL CONTROL CHECK');
    
    SELECT format('ETL_CONTROL has %s batches, Latest status: %s', 
                 COUNT(*), 
                 MAX(status))
    FROM ETL_CONTROL;

    -- 10. Database Size Information
    PERFORM format_validation_header('DATABASE SIZE INFORMATION');
    
    WITH table_sizes AS (
        SELECT
            relname as table_name,
            pg_total_relation_size(relid) as total_bytes,
            pg_table_size(relid) as data_bytes,
            pg_indexes_size(relid) as index_bytes
        FROM pg_catalog.pg_statio_user_tables
        WHERE schemaname = 'public'
    )
    SELECT format('%s: Total Size=%s MB, Data=%s MB, Indexes=%s MB',
                 table_name,
                 ROUND(total_bytes::numeric/1024/1024, 2),
                 ROUND(data_bytes::numeric/1024/1024, 2),
                 ROUND(index_bytes::numeric/1024/1024, 2))
    FROM table_sizes
    ORDER BY total_bytes DESC;

END $$;

-- Summary query for quick health check
SELECT 
    'Database Structure Summary' as check_type,
    (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public') as total_tables,
    (SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public') as total_indexes,
    (SELECT COUNT(*) FROM pg_matviews WHERE schemaname = 'public') as total_matviews,
    (SELECT COUNT(*) FROM information_schema.table_constraints 
     WHERE constraint_type = 'FOREIGN KEY' AND table_schema = 'public') as total_fks,
    (SELECT COUNT(*) FROM ETL_CONTROL) as etl_batches;