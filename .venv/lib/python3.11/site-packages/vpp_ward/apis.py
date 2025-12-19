import openmeteo_requests

import requests_cache
import pandas as pd
from retry_requests import retry
import requests
import json



###################################
# PRIVATE APIs

def renewable_assets(county=None, type=""):

    try:
        payload = {
            'county': county,
            'type': type,
        }
        headers = {'Content-Type': "application/json",
                    'Accept': "application/json"}
        response = requests.get("https://energymodels.eng.ed.ac.uk/dres/api/renewables/",params=payload)
        data = response.json()
        df = pd.DataFrame(data['data'])
        
        return df 

    except:
        assert("Please check 'https://energymodels.eng.ed.ac.uk/dres/apis_renewables' for the status of the live API.\n It may be that you now need an key to access this API. Also check for updates to this package.")



###################################
# PUBLIC APIs

def openmeteo(latitude=None, longitude=None, start_date=None, end_date=None,
              fields=["wind_speed_10m", "wind_speed_100m", "wind_gusts_10m"]):
    """
    Credit: 
    https://open-meteo.com/en/docs/historical-weather-api

    To see how this works, visit the above site and enter lat/lon etc. 

    Scroll down to "API Response > Charts and URL", refresh chart.
    The code below originates from the adjacent "Python" tab.
    """

    if latitude == None or longitude == None or start_date == None or end_date == None:
        raise ValueError(
            "Arguments `latitude`, `longitude`, `start_date`, `end_date` must be provided.")

    # Setup the Open-Meteo API client with cache and retry on error
    cache_session = requests_cache.CachedSession('.cache', expire_after=-1)
    retry_session = retry(cache_session, retries=5, backoff_factor=0.2)
    openmeteo = openmeteo_requests.Client(session=retry_session)

    # Make sure all required weather variables are listed here
    # The order of variables in hourly or daily is important to assign them correctly below
    url = "https://archive-api.open-meteo.com/v1/archive"
    params = {
        "latitude": latitude,
        "longitude": longitude,
        "start_date": start_date,
        "end_date": end_date,
        "hourly": fields,
        "timezone": "GMT"
    }
    responses = openmeteo.weather_api(url, params=params)

    # Process first location. Add a for-loop for multiple locations or weather models
    response = responses[0]
    hourly = response.Hourly()

    # Prepare duct for DataFrame
    hourly_data = {"date": pd.date_range(
        start=pd.to_datetime(hourly.Time(), unit="s", utc=True),
        end=pd.to_datetime(hourly.TimeEnd(), unit="s", utc=True),
        freq=pd.Timedelta(seconds=hourly.Interval()),
        inclusive="left"
    )}
    
    # Unpack hourly data. The order of variables needs to be the same as requested.
    for i in range(len(fields)):
        hourly_data[fields[i]] = hourly.Variables(i).ValuesAsNumpy()
    
    
    hourly_dataframe = pd.DataFrame(data=hourly_data)
    hourly_dataframe.set_index('date', inplace=True)

    return hourly_dataframe
