query = "SELECT * FROM records WHERE id = ?"
cursor.execute(query, (record_id,))
