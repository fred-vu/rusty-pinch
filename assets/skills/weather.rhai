// WEATHER_SKILL_VERSION=2

fn default_location() {
    // Empty location means wttr.in resolves weather from requester IP.
    return "";
}

fn normalize_mode(raw_mode) {
    let mode = raw_mode;
    mode.trim();

    if mode == "forecast" || mode == "Forecast" || mode == "FORECAST" {
        return "forecast";
    }
    if mode == "rain" || mode == "Rain" || mode == "RAIN" {
        return "rain";
    }
    if mode == "detail" || mode == "Detail" || mode == "DETAIL" {
        return "detail";
    }

    return "current";
}

fn normalize_location(raw_location) {
    let location = raw_location;
    location.trim();

    if is_here_alias(location) {
        return default_location();
    }

    location.replace(" ", "+");
    return location;
}

fn is_here_alias(raw_location) {
    let location = raw_location;
    location.trim();

    if location.len() == 0 {
        return true;
    }

    if location == "here"
        || location == "Here"
        || location == "HERE"
        || location == "local"
        || location == "Local"
        || location == "LOCAL"
        || location == "current"
        || location == "Current"
        || location == "CURRENT"
        || location == "ở đây"
        || location == "o day"
        || location == "tai day" {
        return true;
    }

    return false;
}

fn parse_query(raw_args) {
    let args = raw_args;
    args.trim();

    if args.len() == 0 {
        return ["current", default_location()];
    }

    // Args contract:
    // - "<location>"                        -> current weather
    // - "forecast|<location>"               -> forecast (v2)
    // - "rain|<location>"                   -> precipitation-focused line
    // - "detail|<location>"                 -> detailed current conditions
    let parts = args.split("|");
    if parts.len() >= 2 {
        let mode = normalize_mode(parts[0]);
        let location = parts[1];
        location.trim();

        if location.len() == 0 {
            return [mode, default_location()];
        }

        return [mode, location];
    }

    return ["current", args];
}

fn build_url(mode, encoded_location) {
    let base = "https://wttr.in";
    if encoded_location.len() > 0 {
        base = base + "/" + encoded_location;
    }

    if mode == "forecast" {
        return base + "?format=v2";
    }

    if mode == "rain" {
        return base + "?format=%l:+%c+%p";
    }

    if mode == "detail" {
        return base + "?0";
    }

    return base + "?format=%l:+%c+%t+(feels+like+%f),+%w+wind,+%h+humidity";
}

fn fetch_weather(mode, location) {
    let encoded_location = normalize_location(location);
    let url = build_url(mode, encoded_location);
    let location_label = if encoded_location.len() == 0 { "(auto-ip)" } else { location };

    log_info("weather skill request mode=" + mode + " location=" + location_label + " at=" + time_now());

    let response = http_get(url);
    response.trim();

    if response.len() == 0 {
        if encoded_location.len() == 0 {
            return "No weather data returned for current IP location";
        }
        return "No weather data returned for " + location;
    }

    return response;
}

fn main() {
    return fetch_weather("current", default_location());
}

fn main(args) {
    let query = parse_query(args);
    let mode = query[0];
    let location = query[1];
    return fetch_weather(mode, location);
}
