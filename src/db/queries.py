"""
Standard SQL queries used throughout the application.
These are separated to make them easier to maintain and update.
"""

# Database structure queries
TABLES_QUERY = """
    SELECT 
        t.table_schema,
        t.table_name,
        pg_relation_size(quote_ident(t.table_schema) || '.' || quote_ident(t.table_name)) as table_size_bytes,
        pg_total_relation_size(quote_ident(t.table_schema) || '.' || quote_ident(t.table_name)) as total_size_bytes,
        (SELECT count(*) FROM information_schema.columns c WHERE c.table_schema = t.table_schema AND c.table_name = t.table_name) as column_count,
        COALESCE(obj_description(
            (quote_ident(t.table_schema) || '.' || quote_ident(t.table_name))::regclass::oid, 
            'pg_class'
        ), '') as table_description,
        s.n_live_tup as estimated_row_count
    FROM 
        information_schema.tables t
    JOIN
        pg_stat_user_tables s ON t.table_schema = s.schemaname AND t.table_name = s.relname
    WHERE 
        t.table_schema NOT IN ('pg_catalog', 'information_schema')
        AND t.table_type = 'BASE TABLE'
    ORDER BY 
        t.table_schema, t.table_name
"""

COLUMNS_QUERY = """
    SELECT 
        c.table_schema,
        c.table_name,
        c.column_name,
        c.data_type,
        c.character_maximum_length,
        c.is_nullable,
        c.column_default,
        COALESCE(pg_catalog.col_description(
            format('%I.%I', c.table_schema, c.table_name)::regclass::oid, 
            c.ordinal_position
        ), '') as column_description
    FROM 
        information_schema.columns c
    WHERE 
        c.table_schema NOT IN ('pg_catalog', 'information_schema')
    ORDER BY 
        c.table_schema, c.table_name, c.ordinal_position
"""

INDEXES_QUERY = """
    SELECT
        schemaname as table_schema,
        relname as table_name,
        indexrelname as index_name,
        pg_get_indexdef(indexrelid) as index_definition,
        idx_scan as index_scans,
        idx_tup_read as tuples_read,
        idx_tup_fetch as tuples_fetched,
        pg_relation_size(indexrelid) as index_size_bytes
    FROM
        pg_stat_user_indexes
    WHERE
        schemaname NOT IN ('pg_catalog', 'information_schema')
    ORDER BY
        schemaname, relname, indexrelname
"""

FOREIGN_KEYS_QUERY = """
    SELECT
        tc.table_schema,
        tc.table_name,
        kcu.column_name,
        ccu.table_schema AS foreign_table_schema,
        ccu.table_name AS foreign_table_name,
        ccu.column_name AS foreign_column_name
    FROM
        information_schema.table_constraints tc
    JOIN
        information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
        AND tc.table_schema = kcu.table_schema
    JOIN
        information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name
        AND ccu.table_schema = tc.table_schema
    WHERE
        tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_schema NOT IN ('pg_catalog', 'information_schema')
    ORDER BY
        tc.table_schema, tc.table_name
"""

# Slow query analysis
SLOW_QUERIES_QUERY = """
    SELECT 
        query,
        calls,
        total_exec_time / calls as avg_exec_time_ms,
        total_exec_time as total_time_ms,
        rows / calls as avg_rows,
        max_exec_time as max_time_ms,
        mean_exec_time as mean_time_ms,
        stddev_exec_time as stddev_time_ms,
        min_exec_time as min_time_ms
    FROM pg_stat_statements
    WHERE total_exec_time / calls >= %s
    ORDER BY avg_exec_time_ms DESC
    LIMIT %s
"""

CHECK_EXTENSION_QUERY = """
    SELECT COUNT(*) as count FROM pg_extension WHERE extname = 'pg_stat_statements'
"""

# Table statistics
TABLE_STATS_QUERY = """
    SELECT 
        schemaname, 
        relname as table_name, 
        n_live_tup as row_count,
        n_dead_tup as dead_tuples,
        seq_scan,
        idx_scan
    FROM pg_stat_user_tables
    WHERE relname IN ({})
"""

# Index information
INDEX_INFO_QUERY = """
    SELECT
        schemaname as table_schema,
        relname as table_name,
        indexrelname as index_name,
        pg_get_indexdef(indexrelid) as index_definition,
        idx_scan as index_scans,
        idx_tup_read as tuples_read,
        idx_tup_fetch as tuples_fetched
    FROM
        pg_stat_user_indexes
    WHERE
        relname IN ({})
    ORDER BY
        schemaname, relname, indexrelname
"""

# Schema information
SCHEMA_INFO_QUERY = """
    SELECT 
        table_name, 
        column_name, 
        data_type,
        character_maximum_length,
        is_nullable,
        column_default
    FROM 
        information_schema.columns
    WHERE 
        table_name IN ({})
        AND table_schema = 'public'
    ORDER BY 
        table_name, 
        ordinal_position
"""

# Index recommendation queries
TABLE_STATS_FOR_INDEX_QUERY = """
    SELECT 
        schemaname, 
        relname as table_name, 
        n_live_tup as row_count,
        seq_scan,
        seq_tup_read,
        idx_scan,
        idx_tup_fetch
    FROM pg_stat_user_tables
    WHERE relname = %s
"""

COLUMNS_FOR_INDEX_QUERY = """
    SELECT 
        column_name, 
        data_type,
        is_nullable
    FROM information_schema.columns
    WHERE table_name = %s
    ORDER BY ordinal_position
"""

INDEXES_FOR_TABLE_QUERY = """
    SELECT
        i.relname as index_name,
        array_agg(a.attname) as column_names,
        ix.indisunique as is_unique,
        ix.indisprimary as is_primary,
        am.amname as index_type,
        pg_get_indexdef(ix.indexrelid) as index_definition
    FROM
        pg_class t,
        pg_class i,
        pg_index ix,
        pg_attribute a,
        pg_am am
    WHERE
        t.oid = ix.indrelid
        AND i.oid = ix.indexrelid
        AND a.attrelid = t.oid
        AND a.attnum = ANY(ix.indkey)
        AND t.relkind = 'r'
        AND t.relname = %s
        AND i.relam = am.oid
    GROUP BY
        i.relname,
        ix.indisunique,
        ix.indisprimary,
        am.amname,
        ix.indexrelid
    ORDER BY
        i.relname
"""

# PostgreSQL settings
SETTINGS_QUERY = """
    SELECT name, setting, unit, category, short_desc, context, source
    FROM pg_settings
    ORDER BY category, name
"""

SETTINGS_FILTERED_QUERY = """
    SELECT name, setting, unit, category, short_desc, context, source
    FROM pg_settings
    WHERE name ILIKE %s
    ORDER BY category, name
"""