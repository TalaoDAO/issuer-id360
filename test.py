def check_country(country_code: str):
    banned_countries=["AFG","BRB","BFA","KHM","CYM","COD","PRK","GIB","HTI","IRN","JAM","JOR","MLI","MAR","MOZ","MMR","PAN","PHL","SEN","SSD","SYR","TZA","TTO","UGA","ARE","VUT","YEM"]
    print(len(banned_countries))
    for code in banned_countries:
        print(code)
        if code==country_code:
            return False
    return True
print(check_country("BFA"))