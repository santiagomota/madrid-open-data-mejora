import pandas as pd
from great_expectations.dataset import PandasDataset

df = pd.read_parquet("data/processed/trafico_realtime.parquet")
gdf = PandasDataset(df)

gdf.expect_column_values_to_not_be_null("fecha_hora")
gdf.expect_column_values_to_be_between("ocupacion", min_value=0, max_value=100)
gdf.expect_column_values_to_be_between("nivelServicio", min_value=0, max_value=3)
gdf.expect_table_row_count_to_be_between(1, 50000)

print(gdf.validate())
