def check_birth_date(birth_date :str):
    year=birth_date.split("-")[0]
    if int(year)>2023:
        return str(int(year)-100)+"-"+birth_date.split("-")[1]+"-"+birth_date.split("-")[2]
    else:
        return birth_date

print(check_birth_date("2063-05-12"))