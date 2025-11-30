add_executable(exact_pm exact_pm.cpp)
# exact_pm_assessed

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(exact_pm PRIVATE cxx_std_20)

target_link_libraries(exact_pm
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)