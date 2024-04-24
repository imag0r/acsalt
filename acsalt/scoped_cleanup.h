#pragma once

namespace detail
{
    template <typename Functor>
    struct scoped_cleanup_guard : boost::noncopyable
    {
        scoped_cleanup_guard(Functor f) :
            functor_(std::move(f)),
            active_(true)
        {
        }

        scoped_cleanup_guard(scoped_cleanup_guard&& other) :
            functor_(std::move(other.functor_)),
            active_(other.active_)
        {
            other.active_ = false;
        }

        ~scoped_cleanup_guard()
        {
            try
            {
                if (active_)
                {
                    functor_();
                }
            }
            catch (...)
            {
            }
        }

    private:
        Functor functor_;
        bool active_;
    };
}

template <typename Functor>
detail::scoped_cleanup_guard<typename std::decay<Functor>::type> scoped_cleanup(Functor&& f)
{
    return std::forward<Functor>(f);
}
