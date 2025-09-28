add_executable(exact_pm exact_pm.cpp)
# exact_pm_assessed
add_executable(exact_pm_assessed exact_pm_assessed.cpp)
target_compile_features(exact_pm_assessed PRIVATE cxx_std_17)

target_link_libraries(exact_pm_assessed PRIVATE
  motion
  Boost::program_options      # <- quan trọng, thiếu cái này gây lỗi bạn thấy
  Boost::json                 # nếu file có dùng JSON
  Boost::log Boost::log_setup # nếu dùng logger
  fmt::fmt                    # nếu có dùng fmt
)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(exact_pm PRIVATE cxx_std_20)

target_link_libraries(exact_pm
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)
