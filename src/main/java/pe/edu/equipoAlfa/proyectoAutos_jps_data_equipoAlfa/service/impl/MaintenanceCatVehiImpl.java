package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.impl;

import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CatVehiculosDetallesDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CatVehiculosEditarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CatVehiculosListarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CatVehiculosRegistrarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.CatVehiculos;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.repository.CatVehiculoRepository;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.MaintenanceCatVehiService;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class MaintenanceCatVehiImpl implements MaintenanceCatVehiService {

    @Autowired
    private CatVehiculoRepository catVehiculoRepository;


    //Categoria de Vehiculos

    @Override
    public List<CatVehiculosListarDto> getAllCatVehiculos() {
        List<CatVehiculosListarDto> CatVehiculosList = new ArrayList<>();
        Iterable<CatVehiculos> iterable = catVehiculoRepository.findAll();
        iterable.forEach(CatVehiculos -> {
            CatVehiculosListarDto CatvehiculosListar = new CatVehiculosListarDto(
                    CatVehiculos.getId_cat(),
                    CatVehiculos.getMarca(),
                    CatVehiculos.getActivo(),
                    CatVehiculos.getTipo(),
                    CatVehiculos.getDescripcion()

            );
            CatVehiculosList.add(CatvehiculosListar);
        });
        return CatVehiculosList;
    }

    @Override
    public void registarCatVehi(CatVehiculosRegistrarDto catVehiculosRegistrarDto) {
        CatVehiculos catvehi = new CatVehiculos();
        catvehi.setMarca(catVehiculosRegistrarDto.Marca());
        catvehi.setActivo(catVehiculosRegistrarDto.activo());
        catvehi.setTipo(catVehiculosRegistrarDto.Tipo());
        catvehi.setDescripcion(catVehiculosRegistrarDto.Descripcion());
        catVehiculoRepository.save(catvehi);
    }

    @Override
    public CatVehiculosEditarDto getCatVehiculosEditarDto(int id) {
        Optional<CatVehiculos> optional = catVehiculoRepository.findById(id);
        return optional.map(
                CatVehiculos -> new CatVehiculosEditarDto(
                        CatVehiculos.getId_cat(),
                        CatVehiculos.getMarca(),
                        CatVehiculos.getActivo(),
                        CatVehiculos.getTipo(),
                        CatVehiculos.getDescripcion()
                )
        ).orElse(null);
    }

    @Override
    public void actualizarCatVehi(int id, CatVehiculosEditarDto catVehiculosEditarDto) {
        CatVehiculos catvehi = catVehiculoRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Categoria no encontrada"));

        catvehi.setId_cat(catVehiculosEditarDto.id_cat());
        catvehi.setMarca(catVehiculosEditarDto.Marca());
        catvehi.setActivo(catVehiculosEditarDto.activo());
        catvehi.setTipo(catVehiculosEditarDto.Tipo());
        catvehi.setDescripcion(catVehiculosEditarDto.Descripcion());
        catVehiculoRepository.save(catvehi);

    }


    @Override
    public Boolean eliminarCatVehi(Integer id) throws Exception {
        Optional<CatVehiculos> optional = catVehiculoRepository.findById(id);
        return optional.map(catVehiculos -> {
            catVehiculoRepository.delete(catVehiculos);
            return true;
        }).orElse(false);
    }


    @Override
    public CatVehiculosDetallesDto getCatVehiculoDetalleById(Integer id) {
        Optional<CatVehiculos> optional = catVehiculoRepository.findById(id);
        return optional.map(CatVehiculos -> new CatVehiculosDetallesDto(
                CatVehiculos.getId_cat(),
                CatVehiculos.getMarca(),
                CatVehiculos.getActivo(),
                CatVehiculos.getTipo(),
                CatVehiculos.getDescripcion()
        )).orElse(null);
    }

}
