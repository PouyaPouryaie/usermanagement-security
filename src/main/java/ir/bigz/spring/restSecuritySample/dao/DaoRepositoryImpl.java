package ir.bigz.spring.restSecuritySample.dao;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.management.openmbean.InvalidOpenTypeException;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.io.Serializable;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.List;

@Component
public abstract class DaoRepositoryImpl<T, K extends Serializable> implements DaoRepository<T, K> {

    @PersistenceContext
    private EntityManager entityManager;

    private Class<T> daoType;

//    public void setDaoType(Class<T> daoType){
//        this.daoType = daoType;
//    }

    public DaoRepositoryImpl() {
        Type t = getClass().getGenericSuperclass();
        ParameterizedType pt = (ParameterizedType) t;
        daoType = (Class<T>) pt.getActualTypeArguments()[0];
    }

    @Override
    public Object getORMapper() {
        return entityManager;
    }

    @Override
    public <E> E getORMapper(Class<E> type) {
        if(type == null)
            return null;

        if(!type.isInstance(entityManager)) {
            throw new InvalidOpenTypeException("DaoRepositoryImpl support only the EntityManager type . . .");
        }

        return type.cast(entityManager);
    }


    @Override
    @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
    public <S extends T> S insert(S entity) {
        entityManager.persist(entity);
        return entity;
    }

    @Override
    public <S extends T> Iterable<S> insert(Iterable<S> entities) {
        return null;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
    public <S extends T> S update(S entity) {
        return entityManager.merge(entity);
    }

    @Override
    public <S extends T> Iterable<S> update(Iterable<S> entities) {
        return null;
    }

    @Override
    public <S extends T> void delete(S entity) {

    }

    @Override
    public void delete(K id) {
        entityManager.remove(find(id));
    }

    @Override
    public void deleteAll() {

    }

    @Override
    @Transactional(propagation = Propagation.SUPPORTS, readOnly = true, rollbackFor = Exception.class)
    public List<T> getAll() {
        return entityManager.createQuery("from " + daoType.getName()).getResultList();
    }

    @Override
    @Transactional(propagation = Propagation.SUPPORTS, readOnly = true, rollbackFor = Exception.class)
    public T find(K id) {
        return entityManager.find(daoType, id);
    }

    @Override
    public <S extends T> List<S> find(List<K> entityIds) {
        return null;
    }

    @Override
    public <S extends T> List<S> find(String entityName) {
        return null;
    }

    @Override
    public List<T> genericSearch(String query) {

        return entityManager.createQuery(query, daoType).getResultList();
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
    public void flush() {
        entityManager.flush();
    }

    @Override
    @Transactional(propagation = Propagation.SUPPORTS, readOnly = true, rollbackFor = Exception.class)
    public void clear() {
        entityManager.clear();
    }
}
